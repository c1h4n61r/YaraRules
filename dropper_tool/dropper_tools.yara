rule psexec_generic
{
meta:
	author = "@patrickrolsen"
	reference = "Sysinternals PsExec Generic"
	filetype = "EXE"
	version = "0.1"
	date = "1/29/2014"
strings:
	$s1 = "Pstools\\psexec\\"
	$s2 = "PsInfSvc"
	$s3 = "%s -install"
	$s4 = "%s -remove"
	$s5 = "Usage: psexec"
condition:
	uint16(0) == 0x5A4D and (all of ($s*))
}

rule scanline_mcafee
{
meta:
	author = "@patrickrolsen"
	reference = "http://www.mcafee.com/us/downloads/free-tools/scanline.aspx"
	filetype = "EXE"
	version = "0.1"
	date = "1/30/2014"
strings:
	$s1 = "CPports.txt"
	$s2 = "ICMP Time"
	$s3 = "Foundsto"
	$s4 = "USER"
	$s5 = {55 50 58 ??} // UPX?
condition:
	uint16(0) == 0x5A4D and (all of ($s*))
}

rule blat_email_301
{
meta:
	author = "@patrickrolsen"
strings:
	$s1 = {33 00 2E 00 30 00 2E 00 31} // 301 uni
	$s2 = "Mar  7 2012"
condition:
	uint16(0) == 0x5A4D and (all of ($s*))
}

rule gsec_generic
{
meta:
	author = "@patrickrolsen"
	reference = "GSec Dump"
	filetype = "EXE"
	version = "0.1"
	date = "1/29/2014"
strings:
	$s1 = "gsecdump"
	$s2 = "usage: gsecdump"
	$s3 = "dump hashes from SAM//AD"
	$s4 = "dump lsa secrets"
	$s5 = "dump_"
	$s6 = "dump all secrets"
condition:
	uint16(0) == 0x5A4D and and (all of ($s*))
}

rule bcp_sql_tool
{
meta:
	author = "@patrickrolsen"
	reference = "iSIGHTPartners_ThreatScape_AA_KAPTOXA PDF - 3f00dd56b1dc9d9910a554023e868dac"
	filetype = "EXE"
	version = "0.1"
	date = "1/30/2014"
strings:
	$s1 = "BCP"
	$s2 = "SQLState = %s"
	$s3 = "Warning = %s"
	$s4 = "bcp."
	$s5 = ";database="
	$s6 = "FIRE_TRIGGERS"

condition:
	uint16(0) == 0x5A4D and (all of ($s*))
}

rule osql_tool
{
meta:
	author = "@patrickrolsen"
	reference = "O/I SQL - SQL query tool"
	filetype = "EXE"
	version = "0.1"
	date = "1/30/2014"
strings:
	$s1 = "osql\\src"
	$s2 = "OSQLUSER"
	$s3 = "OSQLPASSWORD"
	$s4 = "OSQLSERVER"
condition:
	uint16(0) == 0x5A4D and (all of ($s*))
}

rule port_forward_tool
{
meta:
	author = "@patrickrolsen"
	reference = "Port Forwarding Tool"
	filetype = "EXE"
	version = "0.1"
	date = "1/30/2014"
strings:
	$s1 = "%d.%d.%d.%d"
	$s2 = "%i.%i.%i.%i on port %i"
	$s3 = "connect to %s:%i"
	$s4 = "%s:%i established"
	$s5 = "%s:%i closed"
condition:
	uint16(0) == 0x5A4D and (all of ($s*))
}







/*
The packer rules I got from these sources:
https://malwarecookbook.googlecode.com/svn-history/r5/trunk/3/4/packer.yara
https://code.google.com/p/malware-lu/source/browse/tools/yara/packer.yara
https://github.com/endgameinc/binarypig/blob/master/yara_rules/userdb_panda.yara


rule _Armadillo_v171
{
meta:
	description = "Armadillo v1.71"
strings:
	$0 = {55 8B EC 6A FF 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 A1}
condition:
	$0 at entrypoint
}

rule _UPX_V200V290
{
meta:
	description = "UPX V2.00-V2.90 -> Markus Oberhumer & Laszlo Molnar & John Reiser"
strings:
	$0 = {FF D5 8D 87 ?? ?? ?? ?? 80 20 ?? 80 60 ?? ?? 58 50 54 50 53 57 FF D5 58 61 8D 44 24 ?? 6A 00 39 C4 75 FA 83 EC 80 E9}
condition:
	$0
}

rule _UPX_v0896
{
meta:
	description = "UPX v0.89.6 - v1.02 / v1.05 - v1.22 DLL"
strings:
	$0 = {80 7C 24 08 01 0F 85 ?? ?? ?? 00 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 83 CD FF}
condition:
	$0 at entrypoint
}

rule _UPX_290_LZMA
{
meta:
	description = "UPX 2.90 [LZMA] -> Markus Oberhumer, Laszlo Molnar & John Reiser"
strings:
	$0 = {60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 83 CD FF EB 10 90 90 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB}
	$1 = {60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 83 CD FF 89 E5 8D 9C 24 ?? ?? ?? ?? 31 C0 50 39 DC 75 FB 46 46 53 68 ?? ?? ?? ?? 57 83 C3 04 53 68 ?? ?? ?? ?? 56 83 C3 04 53 50 C7 03 ?? ?? ?? ?? 90 90}
condition:
	$0 at entrypoint or $1 at entrypoint
}

rule _UPX_Protector_v10x_2
{
meta:
	description = "UPX Protector v1.0x (2)"
strings:
	$0 = {EB ?? ?? ?? ?? ?? 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB}
condition:
	$0
}

rule _Armadillo_v1xx__v2xx
{
meta:
	description = "Armadillo v1.xx - v2.xx"
strings:
	$0 = {55 8B EC 53 8B 5D 08 56 8B 75 0C 57 8B 7D 10 85 F6}
condition:
	$0 at entrypoint
}
*/