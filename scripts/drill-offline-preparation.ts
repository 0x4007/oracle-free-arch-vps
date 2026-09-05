import {
  controllerCidr,
  type DrillPlan,
  drillPlanDigest,
} from "./isolated-drill.ts";
import { shellQuote } from "./backup-guest.ts";
import type { JsonRecord } from "./oci.ts";

export interface DrillGuestBundle {
  planSha256: string;
  files: Record<string, string>;
  masks: string[];
}

/** Files for the copied root only. No source service or network is changed. */
export async function drillGuestBundle(
  plan: DrillPlan,
): Promise<DrillGuestBundle> {
  controllerCidr(plan.controllerIpv4);
  const planSha256 = await drillPlanDigest(plan);
  const firewallDependency =
    `[Unit]\nRequires=arch-drill-firewall.service\nAfter=arch-drill-firewall.service\n`;
  return {
    planSha256,
    files: {
      "etc/arch-drill.nft": `table inet arch_drill {
  chain input {
    type filter hook input priority -300; policy drop;
    iifname "lo" accept
    ip saddr ${plan.controllerIpv4} tcp dport 22 ct state { new, established } accept
    ip saddr 169.254.169.254 udp sport 67 udp dport 68 accept
  }
  chain output {
    type filter hook output priority -150; policy drop;
    oifname "lo" accept
    ip daddr ${plan.controllerIpv4} tcp sport 22 ct state established accept
    ip daddr { 169.254.169.254, 255.255.255.255 } udp sport 68 udp dport 67 accept
  }
  chain forward {
    type filter hook forward priority -300; policy drop;
  }
}
`,
      "etc/systemd/system/arch-drill-firewall.service": `[Unit]
Description=First-boot isolation for the copied Arch restore drill
DefaultDependencies=no
Before=network-pre.target systemd-networkd.service sshd.service
After=local-fs.target

[Service]
Type=oneshot
ExecStart=/usr/bin/nft -f /etc/arch-drill.nft
RemainAfterExit=yes
`,
      "etc/systemd/system/arch-drill.target": `[Unit]
Description=Isolated Arch restore acceptance
Requires=basic.target arch-drill-firewall.service systemd-networkd.service systemd-user-sessions.service systemd-logind.service sshd.service
After=basic.target arch-drill-firewall.service systemd-networkd.service systemd-user-sessions.service systemd-logind.service sshd.service
AllowIsolate=yes
`,
      "etc/systemd/system/systemd-networkd.service.d/arch-drill.conf":
        firewallDependency,
      "etc/systemd/system/sshd.service.d/arch-drill.conf": firewallDependency,
      "etc/systemd/system/user@.service.d/arch-drill.conf": firewallDependency,
      "etc/systemd/network/00-arch-drill.network": `[Match]
Name=e*

[Network]
DHCP=ipv4
IPv6AcceptRA=no
LinkLocalAddressing=no
LLMNR=no
MulticastDNS=no

[DHCPv4]
UseDNS=no
UseNTP=no
UseHostname=no
SendHostname=no
`,
      // This pair predates the source startup repairs. Apply them to the copy.
      "home/codex/.config/systemd/user/vncserver.service.d/backup-recovery.conf":
        `[Service]
ExecStart=
ExecStart=/usr/bin/xinit /etc/X11/tigervnc/Xsession /usr/bin/startxfce4 -- /usr/bin/Xvnc :1 -auth %h/.Xauthority -depth 24 -desktop "arch:1 (codex)" -geometry 1920x1080 -localhost -pn -rfbauth %h/.config/tigervnc/passwd -rfbport 5901 -securitytypes VncAuth
ExecStop=
`,
      "home/codex/.config/systemd/user/codex-remote-daemon.service.d/backup-recovery.conf":
        "[Service]\nRemainAfterExit=yes\n",
    },
    masks: [
      ...[
        "tailscaled.service",
        "firewalld.service",
        "nftables.service",
        "vps-update.service",
        "vps-update.timer",
        "cloud-init.service",
        "cloud-final.service",
        "systemd-imds-early-network.service",
        "systemd-imds-import.service",
        "systemd-imdsd.socket",
        "systemd-imdsd@.service",
      ].map((unit) => `etc/systemd/system/${unit}`),
      ...[
        "tailscaled.service",
        "codex-remote-daemon.service",
        "sync-orgs.service",
        "sync-orgs.timer",
        "codex-metrics.service",
        "codex-metrics.timer",
      ].map((unit) => `home/codex/.config/systemd/user/${unit}`),
    ],
  };
}

export async function drillGuestFilesDigest(
  bundle: DrillGuestBundle,
): Promise<string> {
  const bytes = new TextEncoder().encode(
    JSON.stringify({ files: bundle.files, masks: bundle.masks }),
  );
  return [...new Uint8Array(await crypto.subtle.digest("SHA-256", bytes))].map((
    value,
  ) => value.toString(16).padStart(2, "0")).join("");
}

export interface OfflinePreparationEvidence {
  helper: JsonRecord;
  bootAttachment: JsonRecord;
  rootAttachment: JsonRecord;
  bootVolumeId: string;
  rootVolumeId: string;
  rootUuid: string;
  stagingUuid: string;
  kernelSha256: string;
  initramfsSha256: string;
  grubSha256: string;
}

/** Build a guarded helper operation after reconciling the actual OCI objects.
 * The helper checks its own metadata ID, whole-disk attachment paths, filesystem
 * identities and boot hashes again before mounting or writing only the copies.
 */
export async function offlinePreparationCommand(
  plan: DrillPlan,
  evidence: OfflinePreparationEvidence,
): Promise<string> {
  const { helper, bootAttachment, rootAttachment } = evidence;
  if (
    !helper.id || helper.id === plan.source.instanceId ||
    helper["lifecycle-state"] !== "RUNNING" ||
    helper["compartment-id"] !== plan.source.compartmentId ||
    helper["availability-domain"] !== plan.availabilityDomain ||
    helper["display-name"] !== `arch-drill-helper-${plan.suffix}` ||
    helper["image-id"] !== plan.helperImageId ||
    !evidence.bootVolumeId || !evidence.rootVolumeId ||
    evidence.bootVolumeId === evidence.rootVolumeId ||
    [evidence.bootVolumeId, evidence.rootVolumeId].some((id) =>
      [plan.source.bootVolumeId, plan.source.rootVolumeId].includes(id)
    ) ||
    [bootAttachment, rootAttachment].some((attachment, index) =>
      attachment["instance-id"] !== helper.id ||
      attachment["volume-id"] !==
        (index === 0 ? evidence.bootVolumeId : evidence.rootVolumeId) ||
      attachment["lifecycle-state"] !== "ATTACHED" ||
      attachment["attachment-type"] !== "paravirtualized" ||
      !(index === 0 && attachment.device === null) &&
        (typeof attachment.device !== "string" ||
          !/^\/dev\/oracleoci\/oraclevd[b-z]$/.test(attachment.device))
    ) || bootAttachment.device === rootAttachment.device ||
    ![evidence.rootUuid, evidence.stagingUuid].every((value) =>
      /^[a-f0-9-]{36}$/.test(value)
    ) ||
    ![evidence.kernelSha256, evidence.initramfsSha256, evidence.grubSha256]
      .every((value) => /^[a-f0-9]{64}$/.test(value))
  ) {
    throw new Error(
      "Offline preparation is not bound to the helper and copied disks",
    );
  }
  const bundle = await drillGuestBundle(plan);
  if (await drillGuestFilesDigest(bundle) !== plan.offlineFilesSha256) {
    throw new Error("Offline isolation files differ from the approved plan");
  }
  const payload = btoa(
    Array.from(
      new TextEncoder().encode(JSON.stringify({ plan, evidence, bundle })),
      (byte) => String.fromCharCode(byte),
    ).join(""),
  );
  const script =
    `import base64,hashlib,json,os,pathlib,stat,subprocess,urllib.request
p=json.loads(base64.b64decode('${payload}'))
e=p['evidence']; b=p['bundle']
request=urllib.request.Request('http://169.254.169.254/opc/v2/instance/',headers={'Authorization':'Bearer Oracle'})
with urllib.request.urlopen(request,timeout=10) as response: identity=json.load(response)
assert identity['id']==e['helper']['id'] and identity['id']!=p['plan']['source']['instanceId'], 'Wrong helper instance'
def run(*args): return subprocess.check_output(args,text=True).strip()
def disk(attachment,uuid,fstype,size):
 # OCI forbids an explicit consistent device path for boot volumes attached
 # as data. Resolve only that case from the unique copied filesystem UUID.
 args=['lsblk','--json','--tree','--paths','--bytes','--output','PATH,TYPE,UUID,FSTYPE,SIZE,MOUNTPOINTS']
 if attachment['device'] is not None: args.append(os.path.realpath(attachment['device']))
 else: assert attachment==e['bootAttachment'], 'Only the boot copy may use automatic device discovery'
 tree=json.loads(run(*args))['blockdevices']
 def has_mounts(item):
  return any(item.get('mountpoints') or []) or any(has_mounts(child) for child in item.get('children',[]))
 if attachment['device'] is None:
  tree=[item for item in tree if item['type']=='disk' and not has_mounts(item) and any(child.get('uuid')==uuid and child.get('fstype')==fstype for child in item.get('children',[]))]
 assert len(tree)==1 and tree[0]['type']=='disk' and int(tree[0]['size'])==size, 'Unexpected disk size or type'
 assert stat.S_ISBLK(os.stat(tree[0]['path']).st_mode), 'Attachment is not a block device'
 def unmounted(item):
  assert not any(item.get('mountpoints') or []), 'A copied device is already mounted'
  for child in item.get('children',[]): unmounted(child)
 unmounted(tree[0])
 children=tree[0].get('children',[])
 candidates=[child for child in children if child.get('uuid')==uuid and child.get('fstype')==fstype]
 assert len(candidates)==1, 'Copied partition identity is not unique'
 candidates[0]['diskPath']=tree[0]['path']
 return candidates[0]
root=disk(e['rootAttachment'],e['rootUuid'],'ext4',150*1024**3)
stage=disk(e['bootAttachment'],e['stagingUuid'],'xfs',50*1024**3)
assert int((pathlib.Path('/sys/class/block')/pathlib.Path(root['path']).name/'start').read_text())==1050624, 'Root partition start changed'
base=pathlib.Path('/mnt/arch-drill')
base.mkdir(mode=0o700,exist_ok=True)
assert not base.is_symlink() and not any(base.iterdir()), 'Preparation mount directory is not empty'
r=base/'root';s=base/'stage';r.mkdir();s.mkdir()
mounted=[]
try:
 subprocess.run(['mount','-o','ro,noload',root['path'],str(r)],check=True);mounted.append(r)
 subprocess.run(['mount','-o','ro,norecovery,nouuid',stage['path'],str(s)],check=True);mounted.append(s)
 def digest(path):
  h=hashlib.sha256()
  with path.open('rb') as stream:
   for chunk in iter(lambda:stream.read(1048576),b''): h.update(chunk)
  return h.hexdigest()
 for first,second,expected in [('boot/Image','arch-vmlinuz',e['kernelSha256']),('boot/initramfs-linux.img','arch-initrd.img',e['initramfsSha256'])]:
  assert digest(r/first)==digest(s/second)==expected, 'Backup boot bytes differ from reviewed source'
 assert digest(s/'grub2/grub.cfg')==e['grubSha256'], 'GRUB differs from the reviewed boot configuration'
 grub=(s/'grub2/grub.cfg').read_text()
 assert grub.splitlines()[0]=='set default=0', 'Arch is not the default boot entry'
 assert [line for line in grub.splitlines() if line.startswith('menuentry ')][0]=='menuentry "Arch Linux ARM" {', 'First boot entry is not Arch'
 assert 'set fallback' not in grub, 'Automatic recovery boot is not isolated'
 assert 'root=UUID='+e['rootUuid'] in grub and 'Oracle Linux (fallback)' in grub, 'Boot contract missing'
 assert 'ID=arch' in (r/'etc/os-release').read_text(), 'Copied root is not Arch'
 assert (r/'usr/bin/nft').is_file(), 'Copied nftables executable missing'
 subprocess.run(['mount','-o','remount,rw',str(r)],check=True)
 def target(name):
  path=r/name
  assert not pathlib.PurePosixPath(name).is_absolute() and '..' not in pathlib.PurePosixPath(name).parts
  assert path.parent.resolve().is_relative_to(r.resolve()), 'Copied path escapes root'
  path.parent.mkdir(parents=True,exist_ok=True)
  return path
 # Basic target can activate timers. Mask every copied timer before first boot.
 masks=set(b['masks'])
 for directory,prefix in [('usr/lib/systemd/system','etc/systemd/system'),('etc/systemd/system','etc/systemd/system'),('usr/lib/systemd/user','etc/systemd/user'),('etc/systemd/user','etc/systemd/user'),('home/codex/.config/systemd/user','home/codex/.config/systemd/user')]:
  for timer in (r/directory).glob('*.timer'): masks.add(prefix+'/'+timer.name)
 for name,content in b['files'].items():
  path=target(name)
  assert not path.is_symlink(), 'Unexpected symlink for managed file'
  temporary=path.with_name(path.name+'.arch-drill-new')
  with temporary.open('x') as output: output.write(content);output.flush();os.fsync(output.fileno())
  os.chmod(temporary,0o644);os.replace(temporary,path)
 for name in sorted(masks):
  path=target(name)
  if path.is_symlink() or path.exists(): path.unlink()
  path.symlink_to('/dev/null')
 default=target('etc/systemd/system/default.target')
 if default.is_symlink() or default.exists(): default.unlink()
 default.symlink_to('/etc/systemd/system/arch-drill.target')
 # Match existing user ownership for the restored desktop drop-ins.
 owner=os.stat(r/'home/codex')
 for directory in [r/'home/codex/.config/systemd/user/vncserver.service.d',r/'home/codex/.config/systemd/user/codex-remote-daemon.service.d']:
  os.chown(directory,owner.st_uid,owner.st_gid)
  os.chown(directory/'backup-recovery.conf',owner.st_uid,owner.st_gid)
 for name,content in b['files'].items(): assert target(name).read_text()==content
 for name in masks: assert os.readlink(target(name))=='/dev/null'
 marker=target('etc/arch-drill-prepared.json')
 marker.write_text(json.dumps({'planSha256':b['planSha256'],'bootVolumeId':e['bootVolumeId'],'rootVolumeId':e['rootVolumeId'],'masks':sorted(masks)}))
 os.chmod(marker,0o600)
 os.sync()
 subprocess.run(['mount','-o','remount,ro',str(r)],check=True)
 print(json.dumps({'status':'OFFLINE_FILES_PREPARED','planSha256':b['planSha256'],'firstBootProved':False,'bootDevicePath':stage['diskPath'],'rootDevicePath':root['diskPath']}))
finally:
 for path in reversed(mounted): subprocess.run(['umount',str(path)],check=True)
 for path in [s,r]: path.rmdir()
 base.rmdir()
`;
  return "sudo -n python3 -c " + shellQuote(script);
}
