package main

var QTYPES = map[int]string{
	 0: "RESERVED",
	1: "A",
	2: "NS",
	3: "MD",
	4: "MF",
	5: "CNAME",
	6: "SOA",
	7: "MB",
	8: "MG",
	9: "MR",
	10: "NULL",
	11: "WKS",
	12: "PTR",
	13: "HINFO",
	14: "MINFO",
	15: "MX",
	16: "TXT",
	17: "RP",
	18: "AFSDB",
	19: "X25",
	20: "ISDN",
	21: "RT",
	22: "NSAP",
	23: "NSAP_PTR",
	24: "SIG",
	25: "KEY",
	26: "PX",
	27: "GPOS",
	28: "AAAA",
	29: "LOC",
	30: "NXT",
	31: "EID",
	32: "NIMLOC",
	33: "SRV",
	34: "ATMA",
	35: "NAPTR",
	36: "KX",
	37: "CERT",
	38: "A6",
	39: "DNAME",
	40: "SINK",
	41: "OPT",
	42: "APL",
	43: "DS",
	44: "SSHFP",
	45: "IPSECKEY",
	46: "RRSIG",
	47: "NSEC",
	48: "DNSKEY",
	49: "DHCID",
	50: "NSEC3",
	51: "NSEC3_PARAM",
	52: "TLSA",
	53: "SMIMEA",
	55: "HIP",
	56: "NINFO",
	57: "RKEY",
	58: "TALINK",
	59: "CDS",
	60: "CDNSKEY",
	61: "OPENPGPKEY",
	62: "CSYNC",
	63: "ZONEMD",
	64: "SVCB",
	65: "HTTPS",
	99: "SPF",
	100: "UINFO",
	101: "UID",
	102: "GID",
	103: "UNSPEC",
	104: "NID",
	105: "L32",
	106: "L64",
	107: "LP",
	108: "EUI48",
	109: "EUI64",
	249: "TKEY",
	250: "TSIG",
	251: "IXFR",
	252: "AXFR",
	253: "MAILB",
	254: "MAILA",
	255: "ANY",
	256: "URI",
	257: "CAA",
	258: "AVC",
	259: "DOA",
	260: "AMTRELAY",
	32768: "TA",
	32769: "DLV",
}
var QCLASSES = map[int]string{
	0: "RESERVED",
	1: "IN",
	3: "CH",
	4: "HS",
	254: "NONE",
	255: "ANY",
	65535: "RESERVED",
}
var OPCODES = map[int]string{
	0: "QUERY",
	1: "INVERSE", //obsolete
	2: "STATUS",
	4: "NOTIFY",
	5: "UPDATE",
	6: "DSO",
}
var RCODES = map[int]string{
	0: "NOERROR", //  	No Error 	[RFC1035]
1: "FORMERR", //  	Format Error 	[RFC1035]
2: "SERVFAIL", //  	Server Failure 	[RFC1035]
3: "NXDOMAIN", //  	Non-Existent Domain 	[RFC1035]
4: "NOTIMP", //  	Not Implemented 	[RFC1035]
5: "REFUSED", //  	Query Refused 	[RFC1035]
6: "YXDOMAIN", //  	Name Exists when it should not 	[RFC2136][RFC6672]
7: "YXRRSET", //  	RR Set Exists when it should not 	[RFC2136]
8: "NXRRSET", //  	RR Set that should exist does not 	[RFC2136]
9: "NOTAUTH", //  	Not Authorized 	[RFC8945]
10: "NOTZONE", //  	Name not contained in zone 	[RFC2136]
11: "DSOTYPENI", //  	DSO-TYPE Not Implemented 	[RFC8490]
16: "BADSIG", //  	TSIG Signature Failure 	[RFC8945]
17: "BADKEY", //  	Key not recognized 	[RFC8945]
18: "BADTIME", //  	Signature out of time window 	[RFC8945]
19: "BADMODE", //  	Bad TKEY Mode 	[RFC2930]
20: "BADNAME", //  	Duplicate key name 	[RFC2930]
21: "BADALG", //  	Algorithm not supported 	[RFC2930]
22: "BADTRUNC", //  	Bad Truncation 	[RFC8945]
23: "BADCOOKIE", //  	Bad/missing Server Cookie 	[RFC7873]
}
