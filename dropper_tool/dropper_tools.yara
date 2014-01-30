// Dropper Tools

rule psexec_generic
{
meta:
	author = "@patrickrolsen"
	reference = "Sysinternals PsExec Generic"
	filetype = "EXE"
	version = "0.1"
	date = "1/29/2014"
strings:
	$mz = { 4d 5a } // MZ
	$s1 = "Pstools\\psexec\\"
	$s2 = "PsInfSvc"
	$s3 = "%s -install"
	$s4 = "%s -remove"
	$s5 = "Usage: psexec"
condition:
	($mz at 0) and (all of ($s*))
}

rule blat_email_301
{
meta:
	author = "@patrickrolsen"
strings:
	$mz = { 4d 5a } // MZ
	$s1 = {33 00 2E 00 30 00 2E 00 31} // 301 uni
	$s2 = "Mar  7 2012"
condition:
	($mz at 0) and (all of ($s*))

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
	$mz = { 4d 5a } // MZ
	$s1 = "gsecdump"
	$s2 = "usage: gsecdump"
	$s3 = "dump hashes from SAM//AD"
	$s4 = "dump_wireless"
	$s5 = "dump lsa secrets"
	$s6 = "dump_usedhashes"
	$s7 = "dump_lsa"
	$s8 = "dump all secrets"

condition:
	($mz at 0) and (all of ($s*))

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
	$mz = { 4d 5a } // MZ
	$s1 = "BCP"
	$s2 = "SQLState = %s"
	$s3 = "Warning = %s"
	$s4 = "bcp."
	$s5 = ";database="
	$s6 = "FIRE_TRIGGERS"

condition:
	($mz at 0) and (all of ($s*))

}
