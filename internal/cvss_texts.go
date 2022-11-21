package internal

import (
	"fmt"

	"github.com/goark/go-cvss/v3/metric"
)

// https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator

var (
	AVDescription       = "This metric reflects the context by which vulnerability exploitation is possible. This metric value (and consequently the Base score) will be larger the more remote (logically, and physically) an attacker can be in order to exploit the vulnerable component."
	AVValueDescriptions = map[metric.AttackVector]string{
		metric.AttackVectorNetwork:  "A vulnerability exploitable with Network access means the vulnerable component is bound to the network stack and the attacker's path is through OSI layer 3 (the network layer). Such a vulnerability is often termed 'remotely exploitable' and can be thought of as an attack being exploitable one or more network hops away (e.g. across layer 3 boundaries from routers).",
		metric.AttackVectorAdjacent: "A vulnerability exploitable with Adjacent Network access means the vulnerable component is bound to the network stack, however the attack is limited to the same shared physical (e.g. Bluetooth, IEEE 802.11), or logical (e.g. local IP subnet) network, and cannot be performed across an OSI layer 3 boundary (e.g. a router).",
		metric.AttackVectorLocal:    "A vulnerability exploitable with Local access means that the vulnerable component is not bound to the network stack, and the attacker's path is via read/write/execute capabilities. In some cases, the attacker may be logged in locally in order to exploit the vulnerability, or may rely on User Interaction to execute a malicious file.",
		metric.AttackVectorPhysical: "A vulnerability exploitable with Physical access requires the attacker to physically touch or manipulate the vulnerable component, such as attaching an peripheral device to a system.",
	}
)

var (
	ACDescription       = "The Attack Complexity metric describes the conditions beyond the attacker's control that must exist in order to exploit the vulnerability. As described below, such conditions may require the collection of more information about the target, the presence of certain system configuration settings, or computational exceptions."
	ACValueDescriptions = map[metric.AttackComplexity]string{}
	AC_L                = "Specialized access conditions or extenuating circumstances do not exist. An attacker can expect repeatable success against the vulnerable component."
	AC_H                = "A successful attack depends on conditions beyond the attacker's control. That is, a successful attack cannot be accomplished at will, but requires the attacker to invest in some measurable amount of effort in preparation or execution against the vulnerable component before a successful attack can be expected."
)

var (
	PRDescription       = "This metric describes the level of privileges an attacker must possess before successfully exploiting the vulnerability."
	PRValueDescriptions = map[metric.PrivilegesRequired]string{
		metric.PrivilegesRequiredNone: "The attacker is unauthorized prior to attack, and therefore does not require any access to settings or files to carry out an attack.",
		metric.PrivilegesRequiredLow:  "The attacker is authorized with (i.e. requires) privileges that provide basic user capabilities that could normally affect only settings and files owned by a user. Alternatively, an attacker with Low privileges may have the ability to cause an impact only to non-sensitive resources.",
		metric.PrivilegesRequiredHigh: "The attacker is authorized with (i.e. requires) privileges that provide significant (e.g. administrative) control over the vulnerable component that could affect component-wide settings and files.",
	}
)

var (
	UIDescription       = "This metric captures the requirement for a user, other than the attacker, to participate in the successful compromise of the vulnerable component. This metric determines whether the vulnerability can be exploited solely at the will of the attacker, or whether a separate user (or user-initiated process) must participate in some manner."
	UIValueDescriptions = map[metric.UserInteraction]string{
		metric.UserInteractionNone:     "The vulnerable system can be exploited without interaction from any user.",
		metric.UserInteractionRequired: "Successful exploitation of this vulnerability requires a user to take some action before the vulnerability can be exploited, such as convincing a user to click a link in an email.",
	}
)

var (
	SDescription       = "An important property captured by CVSS v3.0 is the ability for a vulnerability in one software component to impact resources beyond its means, or privileges. This consequence is represented by the metric Authorization Scope, or simply Scope.  For more information see the CVSSv3 Specification (https://www.first.org/cvss/specification-document#i2.2)."
	SValueDescriptions = map[metric.Scope]string{
		metric.ScopeUnchanged: "An exploited vulnerability can only affect resources managed by the same authority. In this case the vulnerable component and the impacted component are the same.",
		metric.ScopeChanged:   "An exploited vulnerability can affect resources beyond the authorization privileges intended by the vulnerable component. In this case the vulnerable component and the impacted component are different.",
	}
)

var (
	CDescription       = "This metric measures the impact to the confidentiality of the information resources managed by a software component due to a successfully exploited vulnerability. Confidentiality refers to limiting information access and disclosure to only authorized users, as well as preventing access by, or disclosure to, unauthorized ones."
	CValueDescriptions = map[metric.ConfidentialityImpact]string{
		metric.ConfidentialityImpactNone: "There is no loss of confidentiality within the impacted component.",
		metric.ConfidentialityImpactLow:  "There is some loss of confidentiality. Access to some restricted information is obtained, but the attacker does not have control over what information is obtained, or the amount or kind of loss is constrained. The information disclosure does not cause a direct, serious loss to the impacted component.",
		metric.ConfidentialityImpactHigh: "There is total loss of confidentiality, resulting in all resources within the impacted component being divulged to the attacker. Alternatively, access to only some restricted information is obtained, but the disclosed information presents a direct, serious impact.",
	}
)

var (
	IDescription       = "This metric measures the impact to the confidentiality of the information resources managed by a software component due to a successfully exploited vulnerability. Confidentiality refers to limiting information access and disclosure to only authorized users, as well as preventing access by, or disclosure to, unauthorized ones."
	IValueDescriptions = map[metric.IntegrityImpact]string{
		metric.IntegrityImpactNone: "There is no loss of confidentiality within the impacted component.",
		metric.IntegrityImpactLow:  "There is some loss of confidentiality. Access to some restricted information is obtained, but the attacker does not have control over what information is obtained, or the amount or kind of loss is constrained. The information disclosure does not cause a direct, serious loss to the impacted component.",
		metric.IntegrityImpactHigh: "There is total loss of confidentiality, resulting in all resources within the impacted component being divulged to the attacker. Alternatively, access to only some restricted information is obtained, but the disclosed information presents a direct, serious impact.",
	}
)

var (
	ADescription       = "This metric measures the impact to the availability of the impacted component resulting from a successfully exploited vulnerability. While the Confidentiality and Integrity impact metrics apply to the loss of confidentiality or integrity of data (e.g., information, files) used by the impacted component, this metric refers to the loss of availability of the impacted component itself, such as a networked service (e.g., web, database, email). Since availability refers to the accessibility of information resources, attacks that consume network bandwidth, processor cycles, or disk space all impact the availability of an impacted component."
	AValueDescriptions = map[metric.AvailabilityImpact]string{
		metric.AvailabilityImpactNone: "There is no impact to availability within the impacted component.",
		metric.AvailabilityImpactLow:  "There is reduced performance or interruptions in resource availability. Even if repeated exploitation of the vulnerability is possible, the attacker does not have the ability to completely deny service to legitimate users. The resources in the impacted component are either partially available all of the time, or fully available only some of the time, but overall there is no direct, serious consequence to the impacted component.",
		metric.AvailabilityImpactHigh: "There is total loss of availability, resulting in the attacker being able to fully deny access to resources in the impacted component; this loss is either sustained (while the attacker continues to deliver the attack) or persistent (the condition persists even after the attack has completed). Alternatively, the attacker has the ability to deny some availability, but the loss of availability presents a direct, serious consequence to the impacted component (e.g., the attacker cannot disrupt existing connections, but can prevent new connections; the attacker can repeatedly exploit a vulnerability that, in each instance of a successful attack, leaks a only small amount of memory, but after repeated exploitation causes a service to become completely unavailable).",
	}
)

func RenderCVSSDetails(cvssBaseMetric *metric.Base) string {
	if cvssBaseMetric == nil {
		return ""
	}

	av := ""
	if v, ok := AVValueDescriptions[cvssBaseMetric.AV]; ok {
		av = v
	}
	ac := ""
	if v, ok := ACValueDescriptions[cvssBaseMetric.AC]; ok {
		ac = v
	}
	pr := ""
	if v, ok := PRValueDescriptions[cvssBaseMetric.PR]; ok {
		pr = v
	}
	ui := ""
	if v, ok := UIValueDescriptions[cvssBaseMetric.UI]; ok {
		ui = v
	}
	s := ""
	if v, ok := SValueDescriptions[cvssBaseMetric.S]; ok {
		s = v
	}
	c := ""
	if v, ok := CValueDescriptions[cvssBaseMetric.C]; ok {
		c = v
	}
	i := ""
	if v, ok := IValueDescriptions[cvssBaseMetric.I]; ok {
		i = v
	}
	a := ""
	if v, ok := AValueDescriptions[cvssBaseMetric.A]; ok {
		a = v
	}

	return StringSanitize(fmt.Sprintf(`
* Attack Vector: %s
* Attack Complexity: %s
* Privileges Required: %s
* User Interaction: %s
* Scope: %s
* Confidentiality Impact: %s
* Integrity Impact: %s
* Availability Impact: %s
`, av, ac, pr, ui, s, c, i, a))
}
