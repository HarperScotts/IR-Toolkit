package analyzer

import (
	"ir-toolkit/internal/model"
	"sort"
)

func projectSystemdSettings(declarations []model.LinuxConfigDirective, values []model.LinuxSystemdValue) []model.LinuxSystemdSetting {
	settings := map[string]*model.LinuxSystemdSetting{}
	for index, declaration := range declarations {
		if declaration.Section != "Service" {
			continue
		}
		rule := ""
		switch declaration.Key {
		case "User", "Group", "WorkingDirectory", "Type", "Restart":
			rule = "last_assignment"
		case "ExecCondition", "ExecStartPre", "ExecStart", "ExecStartPost", "ExecReload", "ExecStop", "ExecStopPost":
			rule = "append_reset"
		default:
			continue
		}
		setting := settings[declaration.Key]
		if setting == nil {
			setting = &model.LinuxSystemdSetting{Section: "Service", Key: declaration.Key, Rule: rule, Values: []model.LinuxSystemdValue{}}
			settings[declaration.Key] = setting
		}
		value := values[index]
		if rule == "last_assignment" {
			setting.Values = []model.LinuxSystemdValue{value}
		} else if declaration.Value == "" {
			setting.Values = []model.LinuxSystemdValue{}
			setting.Resets = append(setting.Resets, value)
		} else {
			setting.Values = append(setting.Values, value)
		}
	}
	names := make([]string, 0, len(settings))
	for name := range settings {
		names = append(names, name)
	}
	sort.Strings(names)
	var result []model.LinuxSystemdSetting
	for _, name := range names {
		result = append(result, *settings[name])
	}
	return result
}
