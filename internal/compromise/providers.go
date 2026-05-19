package compromise

// Liste des fournisseurs 100 % gratuits exposée à l'UI.
var FreeProviders = []map[string]interface{}{
	{
		"id": "xposedornot", "name": "XposedOrNot", "free": true,
		"desc": "Fuites publiques d'emails", "targets": []string{"email"},
	},
	{
		"id": "emailrep", "name": "EmailRep", "free": true,
		"desc": "Réputation & fuites email", "targets": []string{"email"},
	},
	{
		"id": "threatfox", "name": "ThreatFox", "free": true,
		"desc": "IOC malware (abuse.ch)", "targets": []string{"ip", "domain"},
	},
	{
		"id": "urlhaus", "name": "URLhaus", "free": true,
		"desc": "Domaines malware", "targets": []string{"domain"},
	},
	{
		"id": "phishtank", "name": "PhishTank", "free": true,
		"desc": "Sites de phishing", "targets": []string{"domain"},
	},
	{
		"id": "dnsbl", "name": "DNSBL", "free": true,
		"desc": "Blocklists IP (spam/botnet)", "targets": []string{"ip"},
	},
	{
		"id": "shodan", "name": "Shodan InternetDB", "free": true,
		"desc": "Ports & CVE exposés", "targets": []string{"ip"},
	},
}
