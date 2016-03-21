# Copyright (C) 2015  The Software Heritage developers
# See the AUTHORS file at the top-level directory of this distribution
# License: GNU General Public License version 3, or any later version
# See top-level LICENSE file for more information

import unittest

from nose.tools import istest
from nose.plugins.attrib import attr

from swh.model import hashutil

from swh.model import git


_type_to_git_type = {
    'blob': git.GitType.BLOB,
    'tree': git.GitType.TREE,
}


_perms_to_git_perm = {
    '100644': git.GitPerm.BLOB,
    '120000': git.GitPerm.LINK,
    '040000': git.GitPerm.TREE,
    '100755': git.GitPerm.EXEC
}


def to_bytes(path):
    """Convert the string to bytes.

    """
    return path.encode('utf-8', errors='surrogateescape')


def to_hash_data_entry(ls_tree_format_input_line):
    def prepare_str(s):
        return s.strip().replace('\t', ' ').replace('    ', ' ')

    prepared_str = prepare_str(ls_tree_format_input_line)
    perms, type, sha1_git, name = prepared_str.split(' ')
    return {'perms': _perms_to_git_perm[perms],
            'name': to_bytes(name),
            'type': _type_to_git_type[type],
            'sha1_git': bytes.fromhex(sha1_git)}


def to_hash_data(path, ls_tree_format_input):
    entry_lines = ls_tree_format_input.strip().split('\n')
    return {path: list(map(to_hash_data_entry, entry_lines))}


def compute_tree_hash(dirpath, ls_tree_format_input, hex_output):
    hashes = to_hash_data(dirpath, ls_tree_format_input)
    bin_hash = git.compute_directory_git_sha1(dirpath, hashes)
    return hashutil.hash_to_hex(bin_hash)


@attr('slow')
class GitHashTreelib(unittest.TestCase):
    def setUp(self):
        self.to_checks = {
            'e8014cb75cfe9fdb4603ce869eeeb12c53e646d9': """
040000 tree a1e4db2944541e47088e72830464c2ffd3935f47    testing
040000 tree f9375bba7c6d1aabec5ff90b0af53af526b7fc0d    obsolete
100644 blob 1fafc4b0753b4eedf0bc00351286ff864745ab07    README
040000 tree 30d8382c42e9fd66f332d2bebfa44d044afe9d95    removed
040000 tree f3b14ca3821d7d2839713925642261e892270c88    stable
    """,
    '30d8382c42e9fd66f332d2bebfa44d044afe9d95': """
100644 blob a173aecc2f18aedddf1c9882808654febffe0d20    net_dma
100644 blob 0020c49933c45ab0b61cd7e57fa9b4baa672d3c0    devfs
100644 blob c2310b6676f4c78be0a8f8b46ed45a126ca5e57a    dv1394
100644 blob 3243613bc2d2095c86fdd878236dfe08ed0cfe84    ip_queue
100644 blob 20c91adca6d412102dabf73d6b6f387a60d888ec    o2cb
100644 blob ec333e67632266a935daa6e2124744c09caa8d77    raw1394
100644 blob c39c25aee77b13e6d92e46686000ac2d8978da51    video1394
    """,

    'f3b14ca3821d7d2839713925642261e892270c88': """
100644 blob 16d030827368b2c49cbbe396588635dfa69d6c08    firewire-cdev
100644 blob 5eb1545e0b8d2aea38138d8ff43f4045a6b6f729    o2cb
100644 blob c3ae3e7d6a0ccdddedcc61db54910fef59dd54d3    syscalls
100644 blob 964c7a8afb268ae004364b0d71117efa51261dc3    sysfs-acpi-pmprofile
100644 blob 41e5a0cd1e3ed334234c4f3e9e3db1e2fa021dfc    sysfs-bus-firewire
100644 blob 831f15d9672f29e90cca5650356d2f69599e14b8    sysfs-bus-usb
100644 blob 140d85b4ae92faff6d3646735b04974c530c604b    sysfs-bus-w1
100644 blob 3d5951c8bf5fe8b27f47b016289c910f90af97e6    sysfs-bus-xen-backend
100644 blob 70302f370e7ec1c1d46e4d278f41319e1ce536c1    sysfs-class-backlight
100644 blob 097f522c33bb7b5c3632a9ca200e099fea32b2cf    sysfs-class-rfkill
100644 blob 26579ee868c9374ba92d3c1121c94310aacc38b4    sysfs-driver-w1_ds28e04
100644 blob 9f790eebb5d2b0f4d35c317073c72791b41a20b3    sysfs-class-tpm
100644 blob 18d471d9faea9bdec594a5bada594b4062ab66fb    sysfs-class-ubi
100644 blob 85d3dac2e204cfb649969ec6f7570522fb59ed4a    sysfs-class-udc
100644 blob 43f78b88da28beaa556b3bba509f1ac97fa44c16    sysfs-devices
100644 blob 5b2d0f08867cd899df072f89a059995944fb8eec    sysfs-devices-node
100644 blob 33c133e2a631a0d390353f76e4ad0697a568c60f    sysfs-devices-system-cpu
100644 blob caa311d59ac1d24c92643f37b396407a1ab654f0    sysfs-devices-system-xen_memory
100644 blob 7049a2b5035950f3d08dc9e8595a7d40e73036e6    sysfs-driver-ib_srp
100644 blob 9a59d84497edb7c7600e546542b3f4dfbccbe1d2    sysfs-driver-qla2xxx
100644 blob e960cd027e1e9685a83f3275ca859da7a793e116    sysfs-driver-usb-usbtmc
100644 blob e928def14f28c7487e7a319f94a9c1527aaecd8d    sysfs-driver-w1_ds28ea00
100644 blob 5def20b9019e93299ed111d53c338e705b1e2639    sysfs-firmware-efi-vars
100644 blob 32fe7f5c488069c64b8c37951b6dfcfa90f4eb57    sysfs-firmware-opal-dump
100644 blob e1f3058f5954d062796d12feb153d5d025c38495    sysfs-firmware-opal-elog
100644 blob 6272ae5fb36699b9f47276c85ec313185e43a9cf    sysfs-module
100644 blob 636e938d5e33a4e9331a328a05a6b93a0b538e60    sysfs-bus-vmbus
100644 blob ec7af69fea0afd9fe57f6600adc6b9be8fceb90d    sysfs-transport-srp
100644 blob 9723e8b7aeb3125b352b75bc54a0ad0ea7aa2474    thermal-notification
100644 blob 7cdfc28cc2c6d93b861d6ec3acb05bc5aca8bc70    vdso
    """,  # NOQA

    '367b37ab86e8066a46ed8ed81b37e78138aeb7d5': """
    100644 blob 8b7c72f07c92fe87cc7170ecc4fd1edf80fe7791    .gitignore
    100644 blob 06871b0c08a6e9fb5d38f5b1e4d5dfb90135f2f2    Makefile
    100755 blob 8f2629b41c5f5167be37fd3e7dee74dc9b67d2a6    micctrl
    100755 blob 582aad4811ae802844ebeb37d51cc9a1ffec68a8    mpss
    100644 blob 3c5c379fc29d6797d0ce17a837cbda64278f68b3    mpssd.c
    100644 blob f5f18b15d9a057cc6e8d5d1b007424da4d765c0b    mpssd.h
    100644 blob 8dd32693608357df350619a8da6668fb3241afd9    sysfs.c
    """,
            '1f4fa162adf287b4fa3fb762cf54dafc0e671f57': """
100644 blob cd077ca0e1b86dfba53b3bd2d0fa62724eb24eb4	00-INDEX
040000 tree e8014cb75cfe9fdb4603ce869eeeb12c53e646d9	ABI
100644 blob 65022a87bf17902f9e04fe5ecff611a41ffaf4d8	BUG-HUNTING
100644 blob f447f0516f074c700b0c78ca87fcfcf4595ea49f	Changes
100644 blob 1684d0b4efa65880a36d0fb00cc5bff747c3e83a	CodeOfConflict
100644 blob c06f817b3091cdb6e4be6e91dbbb98210177b370	CodingStyle
100644 blob 55b70b903ead2e95ce1226ef0fec3612bea67189	DMA-API-HOWTO.txt
100644 blob edccacd4f048a13e8afdb63db7d98ad41667a503	DMA-API.txt
100644 blob b1a19835e9070dbec2f6dba3d735b8cda23abd6e	DMA-ISA-LPC.txt
100644 blob 18dc52c4f2a0b13a42d9867c36c94f4774bf58e2	DMA-attributes.txt
040000 tree 57c2bd8f00655df1d9ecbeab3a6b265279ae433a	DocBook
040000 tree 902e0d5f0930c22be9b4b6dfe984fe6048626784	EDID
100644 blob 21152d397b88ecbe45bca161444fcee38158e96b	HOWTO
100644 blob 31d1d658827f082f66c88c3147e99be3321635cf	IPMI.txt
100644 blob 01a675175a3674ef88a08ebb4f430dca3a4e4ec2	IRQ-affinity.txt
100644 blob 3a8e15cba816a4ea16fb0208518046214ebff1e6	IRQ-domain.txt
100644 blob 1011e717502162c63a04245169ac05d8f96a895a	IRQ.txt
100644 blob 7b57fc087088f49756eeb8eaabf403bfbbd92b93	Intel-IOMMU.txt
100644 blob bc0548201755e1a8d29614bccbd78fcbbe5a34ae	Makefile
100644 blob a211ee8d8b447354ac3758d2f6f50b901aa41ea0	ManagementStyle
040000 tree 5dc5d1e6756e3547edf8fd663f81ca353545df9d	PCI
040000 tree 7bb4565fcf075c6906c4256b4aab7915c4779ee8	RCU
100644 blob 74be14679ed891820cd9c3a7393007f8dd21d07d	SAK.txt
100644 blob 561826f82093574bc61d887cae0436935d317c5e	SM501.txt
100644 blob a660d494c8edcf9fc9bbaec9887ac6203bfcd60e	SecurityBugs
100644 blob 2b7e32dfe00d95fadabc535372bea6ba343fdc59	SubmitChecklist
100644 blob 31d372609ac00fb715a66174214d10f2ba673520	SubmittingDrivers
100644 blob fd89b04d34f038bafd1485a8f96869828470f619	SubmittingPatches
100644 blob 70acfbf399ebfb86f975ada4b8fbc2055b0ba673	VGA-softcursor.txt
040000 tree bc7ec048cf540e56c5ba839ec9d85bd6eff3f2eb	accounting
040000 tree 3f095916076e489cc63a253019e1a73693f3d3b9	acpi
100644 blob cc2d4ac4f4042b7938e38f9f11970669292839a6	adding-syscalls.txt
040000 tree 9850a7627679a34f8228c0abe8d06bcb4421f784	aoe
100644 blob 77df55b0225ab331bb7268592fa5d18ed8f909c7	applying-patches.txt
040000 tree 35fa24f995536c9d2bcf20c5f842bcc45ce83c86	arm
040000 tree adf0f8637dc105841caeabe57ed9e631802d17fb	arm64
100644 blob 2f2c6cdd73c0c24ab29dcd3f68034f99f17c3125	assoc_array.txt
100644 blob b19fc34efdb17921af43bda0000b13dc82640451	atomic_ops.txt
040000 tree 33c1cd21f36a02c691570dc7dcddf41d8331705d	auxdisplay
040000 tree d6260d3558e94171cfa60b420c8df17a86cc7809	backlight
100644 blob df84162132028d6771fc0da0649f54158bdac93c	bad_memory.txt
100644 blob 8764e9f70821e4f894551f1fb1b98a881f3d3e9d	basic_profiling.txt
100644 blob 32b6c3189d9826a53875ae6dc51ce62e9b86778b	bcache.txt
100644 blob 6b1de70583715d7728a7a31b4612564b0178679b	binfmt_misc.txt
040000 tree cd97febccb0fad00d0d61f0502f6e45c91ed06bf	blackfin
040000 tree 8bbf8033be7139c9897791b4c6ec6611e83de346	block
040000 tree dba91c80d3182baeb0a0ab56d13e49fd785ebec9	blockdev
100644 blob d0d042c2fd5e9e319657117b3de567b2d42a995a	braille-console.txt
100644 blob d8297e4ebd265eb5dd273bad20162e51d369b25a	bt8xxgpio.txt
100644 blob 34916a46c0997dd58e1922a48e08038aab930e02	btmrvl.txt
040000 tree 39641366356afa81c2a52aceeb914f2566c1f4ca	bus-devices
100644 blob 2bc55ff3b4d1e2db24906a41ba71e7da8b900688	bus-virt-phys-mapping.txt
100644 blob 3f9f808b51198b3f6278621b413c872f2b0a494f	cachetlb.txt
040000 tree 8e44d0125c48edbffce58fa03aeaac213868d1ab	cdrom
040000 tree 4d3a7398a2edaa5039706c89a4d7de65a3179282	cgroups
100644 blob 88951b179262a912fcddf16872f302cf117ca4ba	circular-buffers.txt
100644 blob 5c4bc4d01d0c32939af28b3c0044f1700231d4a1	clk.txt
040000 tree 0f0536d144e4d4b9547db48a45a007dfe207e293	cma
100644 blob 7f773d51fdd91acf10e49875abbe66fff0fae767	coccinelle.txt
040000 tree a556d57f754fbaa46c7d0906ebec131e32eb6376	connector
040000 tree 2db84b37022f7520c0c6bbfeec02c546ba553b46	console
040000 tree 11e08c481fb1b35e5faecf7cb926f3d4efe78f87	cpu-freq
100644 blob f9ad5e048b111297549df37cc6a6fc8bff1fc75a	cpu-hotplug.txt
100644 blob 287224e57cfc5d2e75540e7c99cdd9e3f763ff7e	cpu-load.txt
040000 tree 49738b4d2357cb08e9f1368e984815daab99dacd	cpuidle
100644 blob 12b1b25b4da9711c95ab013adf1bec4214964d2c	cputopology.txt
100644 blob a08a7dd9d6255867e88b1ccc51ef820eb635286c	crc32.txt
040000 tree 7737f93e00f6311425f8d52af5ab63dd8bb26d64	cris
040000 tree b2e8f35053e829bb602b71dc937a89c5f4b23c57	crypto
100644 blob e1c52e2dc361607417693946573d8959c7e01b81	dcdbas.txt
100644 blob 172ad4aec493cbe9a9db3b6193a43d8794b231e6	debugging-modules.txt
100644 blob 03703afc4d302e7eeb7fb4031d494ab750233194	debugging-via-ohci1394.txt
100644 blob d262e22bddec06945136bbec0e25826ef2df696e	dell_rbu.txt
040000 tree bc28bfb6c3c0e63023b704090acb200fe2bdb1c1	development-process
040000 tree adccded12cbd61b0f37fd603d09b99df8881cc7e	device-mapper
100644 blob 87b4c5e82d39023094f9b5f9b10cf919e3740f9d	devices.txt
040000 tree 64cd52d94d3e083b1c18cc633552b2550cf23e74	devicetree
100644 blob 3f682889068bf932052737b57071ce715c851eda	digsig.txt
100644 blob 480c8de3c2c44786174e112795f61b2381d3b09f	dma-buf-sharing.txt
040000 tree a75e8c5eb06d2fc0b39427f20afd694f7e30e25a	dmaengine
100644 blob 9de9813d0ec5df101a48428d40cfc9b9d2df6142	dontdiff
040000 tree 213f8c902440f1b0d512b6d0f20252c028828556	driver-model
040000 tree 0ebe2f7c24011ba6c1bae528431dc2c8f11889fc	dvb
100644 blob 9417871b8758f26479e9c90e90a990988d657e8a	dynamic-debug-howto.txt
040000 tree 020529dc9d406d453d30c463702d35e9ee2eef6d	early-userspace
100644 blob 0cf27a3544a5744f39c232c75039a37ca079c2cd	edac.txt
100644 blob 7747024d3bb70023fbff500cd3fc44546b31511b	efi-stub.txt
100644 blob a55e4910924ea98b71969381b47ec16d922ecbdc	eisa.txt
100644 blob 3fa450881ecb8e294a74d17766538804489fe9fd	email-clients.txt
040000 tree 461c382186d40395ee88eba82b2ba8764285a35f	extcon
040000 tree 475212bb9f2a96518b4da5f3fec8fe641e88c7e3	fault-injection
040000 tree 4362119fa45f8ef6c411d2a269178f3bf1b7ed35	fb
040000 tree 8abbff52bbacd5c4251af71bc2e30fd497b5feb0	features
040000 tree 9e2856c144a66c8283dcd3f652edddac59e691bd	filesystems
040000 tree aba7ab22ac20ede93689312a30310a5aa6793178	firmware_class
100644 blob df904aec99044f8056ac530b9e9dc6de8f26f73e	flexible-arrays.txt
040000 tree d4351d91b41949608f281d285520cc06b2b9d4fa	fmc
040000 tree 2368701db45cbe838bc4721bde6ebcbab27b7737	frv
100644 blob 77b36f59d16b452bbf12bba4e3db83ec3ea84a9f	futex-requeue-pi.txt
100644 blob 7b727783db7ed4f87a7c68b44b52054c62f48e85	gcov.txt
100644 blob 7050ce8794b9a4b3dd93b76dd9e2a6d708b468ee	gdb-kernel-debugging.txt
040000 tree bcbdeb421fc8f6bfafa6a770cdbd6815eace6985	gpio
040000 tree ceb5de1b9b291962ccbac05db7a66b6b84a2c802	hid
100644 blob 6bad6f1d1cac4c16e513c491a5a6fb6df0c94786	highuid.txt
100644 blob 6ac6cd51852af538efe38be0147fd585d14601a9	hsi.txt
100644 blob 026e237bbc875ac0401cffaf33376e784da9a0b2	hw_random.txt
040000 tree 0fd3a6b83e05058c3e8396a6f5e0d6d8e740492a	hwmon
100644 blob 61c1ee98e59f2137b8b250d2b469d4d949cca9b3	hwspinlock.txt
040000 tree eac8d0f964d8511d9cf9d1dcced3f3b54ce65c54	i2c
040000 tree dbc729c5c0ad5e8c3b0921948a31695e2667dbdb	ia64
040000 tree 75c7964c0da70c8fb033064f7503e037a181cde1	ide
040000 tree 11cf0e775bfe35ea324fac18f8b6e7882edc1e35	infiniband
100644 blob 535ad5e82b98cb5ed2adad76afc03be347b3af36	init.txt
100644 blob 4e1839ccb555e32c7fc3915dd4a76a0f3664b26f	initrd.txt
040000 tree 7d27d4c0f1e283e3435b24f7a3c9d1a4dc1a8bbc	input
100644 blob 91d89c540709876eadba970228d317faa2dd2153	intel_txt.txt
100644 blob 5ca78426f54c58d10e3fd0030ad51f6ccb2b5b9b	io-mapping.txt
100644 blob 9faae6f26d3227d1799eae90e51471f00b82398d	io_ordering.txt
040000 tree 75305cae2df1b51232f7e663a9d44f8d0a615fbf	ioctl
100644 blob 65f694f2d1c9461c39f2ee71de4f24c7ddc62b02	iostats.txt
100644 blob f6da05670e16d9dcfc3f8b7d50a1a4291ad8a974	irqflags-tracing.txt
100644 blob 400d1b5b523dd8b80d3b5dfbeaf7962611ffd06a	isapnp.txt
040000 tree 6d8fbb1e1d7bf73bd985dbc098ba953ce06db085	isdn
040000 tree 3bcb74b2add6f724ab7f76133dc4471770e03c4d	ja_JP
100644 blob 418020584ccc171b8ff079e496e73383f0f55c29	java.txt
100644 blob 0d32355a4c348ce18cf4540e61a129b4cf2ac3fb	kasan.txt
040000 tree 3e92f27cedbc6a0b52e06e4ba11e57e76826f402	kbuild
040000 tree b508edd7ad1443bff47fc4ac1f843c84abbaaeb1	kdump
100644 blob 78f69cdc9b3fbcec6f32beb179eb4c8732883d5a	kernel-doc-nano-HOWTO.txt
100644 blob eda1eb1451a0881097bfaa8ad76c18acd6945f36	kernel-docs.txt
100644 blob 22a4b687ea5b4b3cb9d576bfeffaed813256a795	kernel-parameters.txt
100644 blob f4cbfe0ba1085b4df3067dcc457219699c5c6150	kernel-per-CPU-kthreads.txt
100644 blob 80aae85d8da6c1b8476fd6824553ae7070e5c508	kmemcheck.txt
100644 blob 18e24abb3ecf61b1f6a214af921af8bd138b27e4	kmemleak.txt
040000 tree b51cd2dcf225f1004e4d23fd80db32f0de7f8ef3	ko_KR
100644 blob 1be59a3a521c87fd6107fcdf64f7c7ac525d1512	kobject.txt
100644 blob 1f9b3e2b98aec9a6687ae14b4f85d7c143729c07	kprobes.txt
100644 blob ddf85a5dde0c12a435b9cbcc30f44159de5acc0b	kref.txt
100644 blob a87d840bacfe11df785995eaee5698f23d565f94	kselftest.txt
040000 tree 652f991d106263d2c68500cf5ad896612945c2b9	laptops
100644 blob 4f80edd14d0a688d2a4cf1cdc491102601a53b9a	ldm.txt
040000 tree 4839303afa967a2104cdaf8aeff6030f27e2b932	leds
100644 blob 407576a233177c3c336827b952872c082207d9e4	local_ops.txt
040000 tree 307372f9d9d08902e22d22034081806aa2fdd6b3	locking
100644 blob 22dd6af2e4bd42152edbe872b224b85a769e7184	lockup-watchdogs.txt
100644 blob 2eae75fecfb965f49065c680063a40c594736ee5	logo.gif
100644 blob 296f0f7f67eb2d73be7ec80106feaf77c5aac163	logo.txt
100644 blob ea45dd3901e3bfa2363bbe7a7009e0fc19809bfd	lzo.txt
040000 tree c40b2eebc8f4266f6374c41dfa30d29d86bb57ea	m68k
100644 blob 28befed9f6102a094702337a229b78c16a94bcde	magic-number.txt
100644 blob 7ed371c852046b3dd5d993db1815d00a9d8f4bc0	mailbox.txt
100644 blob 1b794369e03a4ef14099f4ce702fc0d7c65140c6	md-cluster.txt
100644 blob 1a2ada46aaedae5162499886ec7c532d80c84b82	md.txt
100644 blob f552a75c0e70b22b3800a3fa93c0783075228250	media-framework.txt
100644 blob 2ba8461b0631de759fefd2a12918a6c4f4ee7562	memory-barriers.txt
040000 tree d2fdb444074b09b83d1f74b2a190325606e3f31c	memory-devices
100644 blob ce2cfcf35c27a0d0972547e82f61fbc38c85b5ab	memory-hotplug.txt
100644 blob 30ded732027e2814ccc8c4cf5690a84fbc8ebc30	men-chameleon-bus.txt
040000 tree f0b23005636d2d2e4a4b9f78567895a087610195	metag
040000 tree 29c6681a225b17dbb0cd20b9d73e6d30bb846927	mic
040000 tree 27c1a445222aeb50056defd34a41ea5ba41b7306	mips
040000 tree 11295031a1fb2167d7816e2b4c53272f92489873	misc-devices
040000 tree e45fccc68091d5b9c675558a8667af34923ec594	mmc
040000 tree 1a438a86d22deddb5bf600b21242d0d3c79f0b04	mn10300
100644 blob a78bf1ffa68cb4c4defe32146fc75f8449a46245	module-signing.txt
100644 blob d01ac60521943756a99bfc07fe8fe05e6775626f	mono.txt
040000 tree 3949e1a47604a29499fb37ee66a599004436a00b	mtd
040000 tree d674dc07291045530f4b83ce02ec866765990853	namespaces
040000 tree dbc8596c5816529d45d5339601d1ec9ceab2193b	netlabel
040000 tree 0303625762b34a4fc5ac065d9aa84c489e8141a3	networking
040000 tree 1f4b88a93381592d6b026ad6ed895cc42c551720	nfc
040000 tree 983c152dbf360507b31e2326bb2a35c66eeddf20	nios2
100644 blob ae57b9ea0d4169258b48b0531976b1a4a30eabae	nommu-mmap.txt
100644 blob 1d9bbabb6c79abb04259b78481f7304abacbaccc	ntb.txt
100644 blob 520327790d5431daae3a537d0fd36ec897cde5a8	numastat.txt
040000 tree e11c61ab7124dd21cf150ab4c31bfd1e8fedab88	nvdimm
040000 tree 2d0554d83b8cf9d2d361cc30e9794819658e3f1a	nvmem
100644 blob f3ac05cc23e4abb0ea13277fc8a45873351e7ce3	oops-tracing.txt
100644 blob 7ddfe216a0aa787a52421de6dc8ebc0f3b9002b2	padata.txt
040000 tree 6814a2e66f30688c33b20c88907eaf4e2e0f8059	parisc
100644 blob 120eb20dbb09199afc1628a2ca1187812789bde9	parport-lowlevel.txt
100644 blob c208e4366c033d5bc5d1c40b6d055b7c722656d4	parport.txt
040000 tree 8e50ccd74aeee952f963e0d70cea243bd078f22a	pcmcia
100644 blob 7d3c82431909dd8120322e2360ce32cbd93f87e5	percpu-rw-semaphore.txt
100644 blob b388c5af9e726fe8fdd2eaec09eb1b9374f16b87	phy.txt
040000 tree ea4f357d526fbce14e0c2879c95a8bbafd7b3d5e	phy
100644 blob 9a5bc8651c2923c619b168c1719f1e25e381e368	pi-futex.txt
100644 blob 4976389e432d4dd5207d65ad7c37d407c00d9d87	pinctrl.txt
040000 tree 90cc82c9b546a1c94b1545800b84303562744d1f	platform
100644 blob 763e4659bf186fceff80ae17f50e7b495fe3e7b6	pnp.txt
040000 tree 0487c8fa4b60c90fd12de8c9ef7574d749f9ac4b	power
040000 tree 1d2f3280d25fca0e5a0f703e82177298911df260	powerpc
040000 tree 591eb3d2ce87db9b11b8e84270dfa59ef49854ee	pps
040000 tree 98f3e67e4e4688c5a4e439caed2c6db2ae811d1a	prctl
100644 blob e89ce6624af2fab481a708ad1a0e4e20d1bc0c1c	preempt-locking.txt
100644 blob 2216eb187c213b4c0c5140a760f9df3098150e41	printk-formats.txt
040000 tree da1837f687e5d470a7907a0ece81c877987fd282	pti
040000 tree 962176c51cfe9f3846ab59aafdcc0f07db4e765a	ptp
100644 blob ca895fd211e4e9f5f6bd0fc6a13bf60d9a0c14b2	pwm.txt
100644 blob 5d8675615e59c40c6564710a0a9b73ae060e2a00	ramoops.txt
040000 tree d51ed0cdcddfd9bd8bccbe8169ee47b61fcdc756	rapidio
100644 blob 39873ef41bf9fc1a72b8a2e9ace8284babe74abe	rbtree.txt
100644 blob ef0219fa4bb4cf5beb9078293a92b3ccbcbe0d48	remoteproc.txt
100644 blob 2ee6ef9a6554d600088ae572b3256ffe44e51d08	rfkill.txt
100644 blob 16eb314f56cc45ce923d9354960bdf67ea4e6b98	robust-futex-ABI.txt
100644 blob af6fce23e4847709d32ddee025cafb055326f171	robust-futexes.txt
100644 blob f7edc3aa1e92d4e2eac9ed143212f9757577f041	rpmsg.txt
100644 blob 8446f1ea1410b87b071047dc310a787a92606c31	rtc.txt
040000 tree c7b9d98141594d46c92b026a63f854017c8039e5	s390
040000 tree 5d3736128a6ad1ba76f945c4389034f7aa0b5681	scheduler
040000 tree 1d347ab5c9dce9eb05bf5be505afb6529183f5af	scsi
040000 tree e8e43eadba479833220bf3fa3d1fbaefe9a17991	security
100644 blob 9a7bc8b3f479b2b82dbfa1056df060366dbafdec	serial-console.txt
040000 tree 39133be11e4495c042f2439e984984bec4e63cb6	serial
100644 blob 876c96ae38dba1402e79c11a10ff1c64eb5741fd	sgi-ioc4.txt
040000 tree e6a02a1b02f80ba24307f22431ccceb6fb308838	sh
100644 blob 6b492e82b43d98b93020e033ea1b108adbbf6033	smsc_ece1099.txt
040000 tree 887a845d843820c990ab3cc6251d56a864b9fa34	sound
100644 blob eceab1308a8c2fbde6722232db18bbb57a6e7f2e	sparse.txt
040000 tree 78f79272aa73a95571b1c2d4ea4702b1eaeecb46	spi
100644 blob db3be892afb2b64ee582a5e43ce87223a1251ad3	stable_api_nonsense.txt
100644 blob 3049a612291b1ad8651da72c6081539bb4e83a74	stable_kernel_rules.txt
100644 blob 477927becacba69ee4bdea2203dd796979d14449	static-keys.txt
100644 blob cd66ec836e4f45aae80754ece6c384cfd2f45b95	svga.txt
040000 tree a9a8db7e58ce0082f02604d6f86ab4dd5f32ff9f	sysctl
100644 blob ce60ffa94d2d709681ed339fc4ef25369a2c377d	sysfs-rules.txt
100644 blob 13f5619b2203e68af6d766f66a8137dd1133d4fa	sysrq.txt
040000 tree 9f25dc697646d3ee9505b920a07e4caaf976345d	target
040000 tree 9d4f3319f51b26a7697e109e9d1ba7f435603a5d	thermal
100644 blob 2cbf71975381d0a850d1a254aa76af7957b35058	this_cpu_ops.txt
040000 tree 3e4b4130aa6d96892130c0e74d8efedd6874f4e7	timers
040000 tree d1b46a427ea95f8e3e49dac8b035c3970d794e15	tpm
040000 tree db021902c4a4d411ee1b168b4670e490fa7c1b36	trace
100644 blob a445da098bc6e5aa733cd55ca2ee8b4a5f04dc2c	unaligned-memory-access.txt
100644 blob 4a33f81cadb10165fad3ca7014f83b54f492a4bb	unicode.txt
100644 blob a8643513a5f6cb25851140c021aec4a671c8b62c	unshare.txt
040000 tree bc63f554449a02f3f2d80817327846e127b2c0f1	usb
040000 tree 04a86dfd52c143ed1352758c8e93871cf3c67a2c	vDSO
100644 blob 1dd3fddfd3a1e536de39b69c37168dfc35553a4a	vfio.txt
100644 blob 014423e2824c23fa5b08552e292db52fa25013a7	vgaarbiter.txt
100644 blob e517011be4f964db7b452e1e50420eaed83f143d	video-output.txt
040000 tree 0613d846d1dffae70dabcc998a5fdacd7f5b7a4e	video4linux
040000 tree bfa10f433ac83ca402ed876f705cb0f4a9e31c75	virtual
040000 tree abe2d8a8bbd0f97a2c5485d6adb62c14113bc3d6	vm
100644 blob ca5b82797f6c5c79c949a38cd7d7c19270035993	vme_api.txt
100644 blob db0cb228d64aa4a80a4fe380be3e46439de810e6	volatile-considered-harmful.txt
040000 tree 06051b06aeeee33b30966fbf0b53b241c6261454	w1
040000 tree e796cb3b81fab2327d367e17ba75bac24540c59e	watchdog
040000 tree b48b24715e6929469eb3e7a96eecf7f00e14a607	wimax
100644 blob 5e0e05c5183e290e8d78c531a3f42bc3c85377f7	workqueue.txt
040000 tree 1390d65651d4d0aab960bf20b55d5562c727a81e	x86
100644 blob 81d111b4dc28e15d3ab7471f8be1b8f42fe63e4c	xillybus.txt
040000 tree afee3267cb7f59a0e0236309e27e14985618d523	xtensa
100644 blob 2cf3e2608de324b5622673943807b8e8b353e2da	xz.txt
040000 tree d9c00fe0c456581fc233ad805191be86b387b605	zh_CN
100644 blob 90a64d52bea2f33464f86e4dc93954b2bc105f50	zorro.txt
            """,  # NOQA
            "e202fc2cf10dcc460aaf469db4cb5379bbe326d8":
            """
100644 blob 5b6e7c66c276e7610d4a73c70ec1a1f7c1003259    COPYING
100644 blob 13248728a1c884756a0e265faf5b679ec27f47bc    Copyright
100644 blob d8b02abb7e1a3523a40f8b7cbfb7d05f6fca8557    Makefile.pre
100644 blob 886eacfa48acef07d6d0b5b3b197811ab7775340    README
100755 blob 2a5781c640c10f05d7f194e0f1d24aaa96833e46    configure
040000 tree 656a2f680866edaf80fdfbcc7db503fe06b6772d    doc
100644 blob b4d29e3dd5710423b57f388dfec3acd3d04b76f7    es.cwl
100644 blob b883cd6b699486be32abaeeb15eacdfb4d816893    es.dat
100644 blob 4103348bbbbc69ea08f2c970c3e360794137ed8c    es.multi
100644 blob c3afb3608574b7afa5364468b5267c0824c8f079    espa\udcf1ol.alias
100644 blob c3afb3608574b7afa5364468b5267c0824c8f079    esponol.alias
100644 blob 7926a11dac0dc13055ed8a4ada14b7985a3332f5    info
100644 blob c3afb3608574b7afa5364468b5267c0824c8f079    spanish.alias
"""
    }  # NOQA

    @istest
    def compute_complex_directories_git_sha1(self):
        for sha1 in self.to_checks.keys():
            sha1_input = self.to_checks[sha1]
            self.assertEquals(sha1, compute_tree_hash('some-path', sha1_input,
                                                      sha1))
