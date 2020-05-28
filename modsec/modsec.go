//+build collector_modsec

package modsec

/*
#cgo CFLAGS: -I../build/modsec
#cgo LDFLAGS: -L../build/modsec -lmodsecurity -lmodsecurity-wrapper
#include <library.h>
#include <stdlib.h>
*/
import "C"
import (
	"unsafe"
)

type attrArr struct {
	arr []C.attribute
}

func newAttrArr(count int) *attrArr {
	return &attrArr{
		arr: make([]C.attribute, 0, count),
	}
}

func (a *attrArr) addAttr(key string, value string) {
	a.arr = append(a.arr, C.attribute{C.CString(key), C.CString(value)})
}

func (a *attrArr) cPointer() *C.attribute {
	return (*C.attribute)(unsafe.Pointer(&a.arr[0]))
}

func (a *attrArr) cCount() C.int {
	return C.int(len(a.arr))
}

func (a *attrArr) free() {
	for _, elm := range a.arr {
		C.free(unsafe.Pointer(elm.key))
		C.free(unsafe.Pointer(elm.value))
	}
	a.arr = nil
}

type RuleMatch struct {
	RuleId        string
	RuleMessage   string
	MatchMessage  string
	ParanoiaLevel int
}

type ModsecLib interface {
	Init()
	NewRuleEngine(configDir string, fileName string) error
	NewRuleEngineByRules(rules string) error
	CleanupRuleEngine()
	ProcessAttributes(map[string]string) ([]RuleMatch, error)
}

type modsecError struct {
	message string
}

func (me *modsecError) Error() string {
	return me.message
}

type modsec struct {
	ruleEnginePtr unsafe.Pointer
}

func (ms *modsec) Init() {
	C.modsecurity_init()
}

func (ms *modsec) NewRuleEngine(configDir string, fileName string) error {
	cConfigDir := C.CString(configDir)
	defer C.free(unsafe.Pointer(cConfigDir))

	cFileName := C.CString(fileName)
	defer C.free(unsafe.Pointer(cFileName))

	ms.ruleEnginePtr = C.modsecurity_new_rule_engine(cConfigDir, cFileName)
	if ms.ruleEnginePtr == nil {
		return &modsecError{"Failed to create a rule engine. Check configuration."}
	}
	return nil
}

func (ms *modsec) NewRuleEngineByRules(rules string) error {
	cRules := C.CString(rules)
	defer C.free(unsafe.Pointer(cRules))

	ms.ruleEnginePtr = C.modsecurity_new_rule_engine_by_rules(cRules)
	if ms.ruleEnginePtr == nil {
		return &modsecError{"Failed to create a rule engine. Check rule string."}
	}
	return nil
}

func (ms *modsec) ProcessAttributes(attributeMap map[string]string) ([]RuleMatch, error) {
	count := len(attributeMap)
	attr := newAttrArr(count)
	for key, value := range attributeMap {
		attr.addAttr(key, value)
	}
	cMatches := C.modsecurity_process_attributes(ms.ruleEnginePtr, attr.cPointer(), attr.cCount())
	if cMatches == nil {
		return nil, &modsecError{"Nil pointer returned by lib while processing attributes"}
	}

	ruleMatches := make([]RuleMatch, cMatches.count)
	if cMatches.count == 0 {
		return ruleMatches, nil
	}

	matchSlice := (*[1 << 30]C.rule_match)(unsafe.Pointer(cMatches.match_arr))[:cMatches.count:cMatches.count]

	for i := 0; i < int(cMatches.count); i++ {
		rulePtr := matchSlice[i]
		ruleMatch := RuleMatch{
			RuleId:        C.GoString(rulePtr.rule_id),
			RuleMessage:   C.GoString(rulePtr.rule_message),
			MatchMessage:  C.GoString(rulePtr.match_message),
			ParanoiaLevel: int(rulePtr.paranoia_level),
		}
		ruleMatches[i] = ruleMatch
	}

	C.modsecurity_cleanup_rule_match_wrapper(unsafe.Pointer(cMatches))
	return ruleMatches, nil
}

func (ms *modsec) CleanupRuleEngine() {
	if ms.ruleEnginePtr != nil {
		C.modsecurity_cleanup_rule_engine(ms.ruleEnginePtr)
	}
}

func NewModsecLib() ModsecLib {
	return &modsec{}
}

var _ ModsecLib = (*modsec)(nil)
