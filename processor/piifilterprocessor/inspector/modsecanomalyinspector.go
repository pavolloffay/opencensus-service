//+build collector_modsec

package inspector

import (
	"strconv"

	pb "github.com/census-instrumentation/opencensus-service/generated/main/go/ai/traceable/platform/apiinspection/v1"

	"github.com/census-instrumentation/opencensus-service/modsec"
	"go.uber.org/zap"
)

type modsecanomalyinspector struct {
	logger *zap.Logger
	lib    modsec.ModsecLib
}

type ModsecConfig struct {
	ConfigDir string `mapstructure:"config-dir"`
	FileName  string `mapstructure:"file-name"`
	Rules     string `mapstructure:"rules"`
}

func NewModsecInspector(logger *zap.Logger, modsecConfig ModsecConfig) modsecinspector {
	lib := modsec.NewModsecLib()
	lib.Init()
	if len(modsecConfig.Rules) != 0 {
		err := lib.NewRuleEngineByRules(modsecConfig.Rules)
		if err != nil {
			logger.Warn("Problem initializing modsec lib", zap.Error(err))
			return nil
		}
	} else if len(modsecConfig.ConfigDir) != 0 && len(modsecConfig.FileName) != 0 {
		err := lib.NewRuleEngine(modsecConfig.ConfigDir, modsecConfig.FileName)
		if err != nil {
			logger.Warn("Problem initializing modsec lib", zap.Error(err))
			return nil
		}
	} else {
		logger.Warn("Problem while processing configuration.")
		return nil
	}
	return &modsecanomalyinspector{
		logger: logger,
		lib:    lib,
	}
}

func (mi *modsecanomalyinspector) inspect(message *pb.HttpApiInspection, keyToValuesMap map[string][]*Value) {
	attrMap := make(map[string]string)
	for key, values := range keyToValuesMap {

		if len(values) == 1 {
			attrMap[key] = values[0].OriginalValue
		} else {
			for idx, value := range values {
				if value == nil {
					continue
				}
				attrKey := key + "_" + strconv.Itoa(idx)
				attrMap[attrKey] = value.OriginalValue
			}
		}
	}
	ret, err := mi.lib.ProcessAttributes(attrMap)
	if err != nil {
		mi.logger.Warn("Problem while processing attributes in modsec", zap.Error(err))
		return
	}

	if len(ret) == 0 {
		return
	}

	if message.AnomalyInspection == nil {
		message.AnomalyInspection = &pb.AnomalyInspection{}
	}
	var modSecAnomalies []*pb.ModSecAnomaly

	for _, elem := range ret {
		anomaly := &pb.ModSecAnomaly{
			Id:            elem.RuleId,
			MatchMessage:  elem.MatchMessage,
			RuleMessage:   elem.RuleMessage,
			ParanoiaLevel: int32(elem.ParanoiaLevel),
		}
		modSecAnomalies = append(modSecAnomalies, anomaly)
	}
	message.AnomalyInspection.ModSecAnomalies = modSecAnomalies
}

var _ modsecinspector = (*modsecanomalyinspector)(nil)
