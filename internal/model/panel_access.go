package model

type PanelAccess struct {
	Access     string `json:"access"`
	Generation string `json:"generation"`
}

func (p PanelAccess) Valid() bool {
	return (p.Access == "allow" || p.Access == "block") && len(p.Generation) <= 128
}
