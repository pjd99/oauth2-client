package util

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/TheThingsNetwork/ttn/core/types"

)

type App struct {
	EUI        types.AppEUI `json:"eui"` // TODO: Change to []string
	Name       string       `json:"name"`
	Owner      string       `json:"owner"`
	AccessKeys []string     `json:"accessKeys"`
	Valid      bool         `json:"valid"`
}

/*
func GetAppEUI(ctx log.Interface) types.AppEUI {
	if viper.GetString("app-eui") == "" {
		ctx.Fatal("AppEUI not set. You probably want to run 'ttnctl applications use [appEUI]' to do this.")
	}

	appEUI, err := types.ParseAppEUI(viper.GetString("app-eui"))
	if err != nil {
		ctx.Fatalf("Invalid AppEUI: %s", err)
	}

	return appEUI
}
*/

func (a App) EqualsEUI(appEUI string) bool {  
  if a.EUI.String() == appEUI {
    return true
  } else {
    return false
  }
}

func (a App) UserHasAppEUI(appEUIs []string) bool {
	var isUserApp bool
	
	isUserApp = false
	
	for i := range appEUIs {
		if appEUIs[i] == a.EUI.String(){
			isUserApp = true
		}
	}

	return isUserApp

}

func GetApplications(auth string, authurl string) ([]*App, error) {
	uri := fmt.Sprintf("%s/applications", authurl)
	req, err := NewRequestWithAuth(auth, "GET", uri, nil)
	if err != nil {
		fmt.Errorf("Unable to form applications request: " + err.Error())
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Errorf("Unable to get applications: " + err.Error())
	}
	if resp.StatusCode != http.StatusOK {
		fmt.Printf("Failed to get applications: %s", resp.Status)
	}

	defer resp.Body.Close()
	decoder := json.NewDecoder(resp.Body)
	var apps []*App
	err = decoder.Decode(&apps)
	if err != nil {
		fmt.Errorf("Failed to read applications: " + err.Error())
	}

	return apps, nil
}
