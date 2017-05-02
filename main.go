package main

import (
		"os"
        "io"
        "context"
        "fmt"
		"time"
		"errors"
		l "log"
        "net/http"
		"net/url"
		"html/template"
        "strings"
		"bytes"
		"reflect"
		"strconv"
		"golang.org/x/oauth2"
		"github.com/dgrijalva/jwt-go"
		"github.com/apex/log"
		cliHandler "github.com/pjd99/oauth2-client/util/cli/handler"
		"github.com/pjd99/oauth2-client/util"
		"github.com/TheThingsNetwork/ttn/core/types"
		"github.com/TheThingsNetwork/ttn/core"
		 //"golang.org/x/net/context"
)

var pubKey string = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4f5wg5l2hKsTeNem/V41\nfGnJm6gOdrj8ym3rFkEU/wT8RDtnSgFEZOQpHEgQ7JL38xUfU0Y3g6aYw9QT0hJ7\nmCpz9Er5qLaMXJwZxzHzAahlfA0icqabvJOMvQtzD6uQv6wPEyZtDTWiQi9AXwBp\nHssPnpYGIn20ZZuNlX2BrClciHhCPUIIZOQn/MmqTD31jSyjoQoV7MhhMTATKJx2\nXrHhR+1DcKJzQBSTAGnpYVaqpsARap+nwRipr3nUTuxyGohBTSmjJ2usSeQXHI3b\nODIRe1AuTyHceAbewn8b462yEWKARdpd9AjQW5SIVPfdsz5B6GlYQ5LdYKtznTuy\n7wIDAQAB\n-----END PUBLIC KEY-----\n"

var ctx log.Interface

type Key int

const MyKey Key = 0

const STATIC_URL string = "/static/"
const STATIC_ROOT string = "static/"
const AUTH_URL string = "http://localhost:3846"

type Pagecontext struct {
    Title  string
    Static string
	LoginError string
	Username string
	SelectedAppEUI   string
	SelectedAppName  string
	Admin            bool
	Users []*util.User
	Apps []*util.App
	Devices *ListDevices
}

type ABPDevice struct {
	DevAddr  string 
	NwkSKey  string
	AppSKey  string
	FCntUp   uint32 
	FCntDown uint32 
	Flags    string
	AppEUI   string 
}

type OTAADevice struct {
	DevEUI   string
	DevAddr  string
	NwkSKey  string
	AppSKey  string
	AppKey   string
	FCntUp   uint32 
	FCntDown uint32 
	AppEUI   string
}

type ListDevices struct {
	OTAA []*OTAADevice 
	ABP  []*ABPDevice 
}
// JWT schema of the data it will store
type Fullname struct {
	Firstname string 
	Lastname  string
}

type Claims struct {
	Username string  
	Name     Fullname 
	Email    string  
	Admin    bool
	Active    bool   
}

// A valid oauth2 client (check the store)
var clientConf = oauth2.Config{
        ClientID:     "ttnctl",
        ClientSecret: "",
        RedirectURL:  "http://localhost:3846/callback",
        Scopes:       []string{"offline"},
        Endpoint: oauth2.Endpoint{
                TokenURL: "http://localhost:3846/users/token",
                AuthURL:  "http://localhost:3846/users/auth",
        },
}

func main() {
	
		var logLevel = log.InfoLevel
		ctx = &log.Logger{
			Level:   logLevel,
			Handler: cliHandler.New(os.Stdout),
		}
		ctx.Infof("oauth2 client started")
		// ### oauth2 client ###
        // the following handlers are oauth2 consumers
		http.HandleFunc("/", LoginHandler(clientConf))
        http.HandleFunc("/login", LoginHandler(clientConf))	// complete a resource owner password credentials flow
		http.HandleFunc("/logout", validate(logout))
        http.HandleFunc("/applications", validate(protectedApplications))
		http.HandleFunc("/addapplication", validate(protectedAddApplication))
		http.HandleFunc("/delapplication/", validate(protectedDelApplication))
		http.HandleFunc("/devices/", validate(protectedDevices))
		http.HandleFunc("/device/", validate(protectedDeviceInfo))
		http.HandleFunc("/addabp/", validate(protectedAddABP))
		http.HandleFunc("/addotaa/", validate(protectedAddOTAA))
		http.HandleFunc("/users", validate(protectedUsers))
		http.HandleFunc("/user/", validate(protectedUser))
		http.HandleFunc("/adduser", validate(protectedAddUser))
		http.HandleFunc("/deluser/", validate(protectedDelUser))
		http.HandleFunc("/unlink/", validate(protectedUnlink))
		http.HandleFunc("/link/", validate(protectedLink))
		http.HandleFunc(STATIC_URL, StaticHandler)
        l.Fatal(http.ListenAndServe(":3848", nil))
}

func getPageContext(req *http.Request) (Pagecontext, error){
	claims, ok := req.Context().Value(MyKey).(Claims)
	pagecontext := Pagecontext{}
	if !ok {
		return pagecontext, errors.New("No username found")
	}
	
	pagecontext.Username = claims.Username
	pagecontext.Admin = claims.Admin
	
	return pagecontext, nil
}



// move parse templates to main to be ready for use
func render(rw http.ResponseWriter, tmpl string, pagecontext Pagecontext) {
    pagecontext.Static = STATIC_URL
	var tmpl_list []string
	// Do not load base html for login pages
	if tmpl != "login" && tmpl != "logout"{
		tmpl_list = append(tmpl_list, "templates/base.html")
	}
	
	//tmpl_list := []string{"templates/base.html", fmt.Sprintf("templates/%s.html", tmpl)}	
	tmpl_list = append(tmpl_list, fmt.Sprintf("templates/%s.html", tmpl))
	
	// Addditional templates for devices page
	if tmpl == "devices"{
		tmpl_list = append(tmpl_list, "templates/otaainfo.html")
		tmpl_list = append(tmpl_list, "templates/abpinfo.html")
	}
	
	
    t, err := template.ParseFiles(tmpl_list...)
    if err != nil {
        fmt.Println("template parsing error: ", err)
    }
    err = t.Execute(rw, pagecontext)
    if err != nil {
        fmt.Println("template executing error: ", err)
    }
}

func StaticHandler(rw http.ResponseWriter, req *http.Request) {
    static_file := req.URL.Path[len(STATIC_URL):]
    if len(static_file) != 0 {
        f, err := http.Dir(STATIC_ROOT).Open(static_file)
        if err == nil {
            content := io.ReadSeeker(f)
            http.ServeContent(rw, req, static_file, time.Now(), content)
            return
        }
    }
    http.NotFound(rw, req)
}

func getAppName(auth string, appEui string) string {
	
	var appName string
	
	// check AppEUI provided is owned by user
	apps, err := util.GetApplications(auth, AUTH_URL)
	if err != nil {
		fmt.Errorf("Failed to get application list" + err.Error())
		return appName
	}
	for _, app := range apps {
		if app.EUI.String() == appEui {
			appName = app.Name
		}
	}
	
	return appName
}

func refreshToken(rw http.ResponseWriter, req *http.Request)  error {
	
	cookie, err := req.Cookie("Refresh")
	if err != nil {
		fmt.Println("no cookie found")
		http.NotFound(rw, req)
		return err
	}
	
	auth, err := util.RefreshToken(AUTH_URL, cookie.Value)
	 
     if err != nil {
 		fmt.Println("unable to refresh cookie")
 		http.NotFound(rw, req)
 		return err
     } 
	
	expireCookie := time.Now().Add(time.Hour * 2)
	authCookie := http.Cookie{Name: "Auth", Value: auth.AccessToken, Expires: expireCookie, HttpOnly: true}
	refreshCookie := http.Cookie{Name: "Refresh", Value: auth.RefreshToken, Expires: expireCookie, HttpOnly: true}
	http.SetCookie(rw, &authCookie)
	http.SetCookie(rw, &refreshCookie)
	return nil
}

func validate(page http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		cookie, err := req.Cookie("Auth")
		if err != nil {
			fmt.Println("no cookie found")
			pagecontext := Pagecontext{}
			pagecontext.Title = "Logged out"
			render(rw, "logout", pagecontext)
			//http.NotFound(rw, req)
			return
		}
		
		token, err := jwt.Parse(cookie.Value, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
				return nil, fmt.Errorf("Unexpected signing method")
			}
        	anoPubKey, err := jwt.ParseRSAPublicKeyFromPEM([]byte(pubKey))
        	if err != nil {
        		fmt.Errorf("failed to parse DER encoded public key: " + err.Error())
        	}
        	return anoPubKey, nil
		})
		if err != nil {
			fmt.Printf("Cookie Token : %s\n", cookie.Value)
			fmt.Printf("failed to parse token: " + err.Error())
			http.NotFound(rw, req)
			return
		}
		
		if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
			
			var isAdmin bool = false
			
			scope := claims["scope"]
			
			switch reflect.TypeOf(scope).Kind() {
				case reflect.Slice:
					s := reflect.ValueOf(scope)				
					for i := 0; i < s.Len(); i++ {
						if s.Index(i).Interface() == "admin"{
							fmt.Println("User is Admin")
							isAdmin = true
						}
					}
			}
			
		    usrnm := claims["username"].(string)
			nm := claims["name"].(map[string]interface{})
		    fnm :=	nm["first"].(string)
		   	lnm :=  nm["last"].(string)
			email := claims["email"].(string)
			active := claims["valid"].(bool)
			fmt.Printf("Username : %s\n", usrnm)
			fmt.Printf("Name : %s %s\n", fnm, lnm)
			fmt.Printf("User email : %s\n", email)
			
			clm := &Claims{ Username: usrnm,
							Name:     Fullname{ Firstname: fnm, 
							                    Lastname:  lnm, },
							Email:    email,
							Admin:    isAdmin,
							Active:    active, }
			
			contx := context.WithValue(req.Context(), MyKey, *clm)
			//ctx := req.Context()
			page(rw, req.WithContext(contx))
			fmt.Println("user token validated")
		} else {
			http.NotFound(rw, req)
			return
		}
		
	})
}

func LoginHandler(c oauth2.Config) func(rw http.ResponseWriter, req *http.Request) {
        return func(rw http.ResponseWriter, req *http.Request) {
			if req.Method == "GET" {
					pagecontext := Pagecontext{Title: "RF Proximity LoRa Server"}
					render(rw, "login", pagecontext)
			        //t, _ := template.ParseFiles("templates/login.html")
					//t.Execute(rw, nil)
			    } else {
					req.ParseForm()
	                token, err := c.PasswordCredentialsToken(oauth2.NoContext, req.Form.Get("username"), req.Form.Get("password"))
	                if err != nil {
						fmt.Errorf("Failed to login" + err.Error())
						pagecontext := Pagecontext{Title: "RF Proximity LoRa Server", LoginError: "Invalid login credentials"}
						render(rw, "login", pagecontext)
	                    return
	                } else {
						expireCookie := time.Now().Add(time.Hour * 2)
						authCookie := http.Cookie{Name: "Auth", Value: token.AccessToken, Expires: expireCookie, HttpOnly: true}
						refreshCookie := http.Cookie{Name: "Refresh", Value: token.RefreshToken, Expires: expireCookie, HttpOnly: true}
						http.SetCookie(rw, &authCookie)
						http.SetCookie(rw, &refreshCookie)
						http.Redirect(rw, req, "/applications", 307)
	                    return
	                }
			    }
        }
}

func logout(rw http.ResponseWriter, req *http.Request) {
	deleteAuthCookie := http.Cookie{Name: "Auth", Value: "none", Expires: time.Now()}
	http.SetCookie(rw, &deleteAuthCookie)
	
	deleteRefreshCookie := http.Cookie{Name: "Refresh", Value: "none", Expires: time.Now()}
	http.SetCookie(rw, &deleteRefreshCookie)
	
	pagecontext := Pagecontext{}
	pagecontext.Title = "Logged out"
	render(rw, "logout", pagecontext)
	//http.Redirect(rw, req, "/login", 307)
	return
}



// only viewable if the client has a valid token
func protectedApplications(rw http.ResponseWriter, req *http.Request) {
	//Get applications via API
	cookie, err := req.Cookie("Auth")
	if err != nil {
		fmt.Println("no cookie found")
		http.NotFound(rw, req)
		return
	}
	
	// check AppEUI provided is owned by user
	apps, err := util.GetApplications(cookie.Value, AUTH_URL)
	if err != nil {
		fmt.Errorf("Failed to get application list" + err.Error())
	}
	for _, app := range apps {
		fmt.Printf("Application found: %s", app.EUI.String())
	}
	
	pagecontext, err := getPageContext(req)
	if err != nil {
		fmt.Errorf("Failed to get page context" + err.Error())
	}
	pagecontext.Title = "Applications"
	pagecontext.Apps = apps
	render(rw, "applications", pagecontext)
}


func protectedAddApplication(rw http.ResponseWriter, req *http.Request) {
	
	if req.Method == "GET" {
		
		pagecontext, err := getPageContext(req)
		if err != nil {
			fmt.Errorf("Failed to get page context" + err.Error())
		}
		pagecontext.Title = "Add Application"
		render(rw, "addapplication", pagecontext)
		
		
	} else if req.Method == "POST" {
		
		req.ParseForm()
		
		appName := req.Form.Get("AppName")
		appEUI := req.Form.Get("AppEui")
		
		fmt.Printf("ADD App Name: %s\n", appName)
		fmt.Printf("ADD App EUI: %s\n", appEUI)
		
		cookie, err := req.Cookie("Auth")
		if err != nil {
			fmt.Println("no cookie found")
			http.NotFound(rw, req)
			return
		}
		
		uri := fmt.Sprintf("%s/applications", AUTH_URL)
		values := url.Values{
			"name": {appName},
			"appeui": {appEUI},
		}
		authreq, err := util.NewRequestWithAuth(cookie.Value, "POST", uri, strings.NewReader(values.Encode()))
		if err != nil {
			ctx.Infof("Failed to create authenticated request: %s", err)
		}

		authreq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		client := &http.Client{}
		resp, err := client.Do(authreq)
		if err != nil {
			ctx.Infof("Failed to create application, error: %s", err)
		}
		if resp.StatusCode != http.StatusCreated {
			ctx.Infof("Failed to create application, response: %s", resp.Status)
		}

		ctx.Info("Application created successfully")
		
		
		
		http.Redirect(rw, req, "/applications", 307)
		return
	}
	
	
}

func protectedDelApplication(rw http.ResponseWriter, req *http.Request) {
	
	cookie, err := req.Cookie("Auth")
	if err != nil {
		fmt.Println("no cookie found")
		http.NotFound(rw, req)
		return
	}
	
	appEUI, err := types.ParseAppEUI(req.URL.Path[len("/delapplication/"):])
	if err != nil {
		ctx.Infof("Invalid AppEUI: %s", err)
		http.NotFound(rw, req)
		return
	}
	
	uri := fmt.Sprintf("%s/applications/%s", AUTH_URL, appEUI.String())
	authreq, err := util.NewRequestWithAuth(cookie.Value, "DELETE", uri, nil)
	if err != nil {
		ctx.Infof("Failed to create authenticated request: %s", err)
	}

	client := &http.Client{}
	resp, err := client.Do(authreq)
	if err != nil {
		ctx.Infof("Failed to delete application:: %s", err)
	}
	if resp.StatusCode != http.StatusOK {
		ctx.Infof("Failed to delete application:: %s", err)
	}

	ctx.Info("Application deleted successfully")
	
	http.Redirect(rw, req, "/applications", 307)
	
}

func protectedDevices(rw http.ResponseWriter, req *http.Request) {
	// Get app EUI and list devices
	cookie, err := req.Cookie("Auth")
	if err != nil {
		fmt.Println("no cookie found")
		http.NotFound(rw, req)
		return
	}
	
	
	manager := util.GetHandlerManager(ctx)
	
	appEUI, err := types.ParseAppEUI(req.URL.Path[len("/devices/"):])
	if err != nil {
		ctx.Infof("Invalid AppEUI: %s", err)
		http.NotFound(rw, req)
		return
	}
	
	var abpSlice []*ABPDevice
	var otaaSlice []*OTAADevice
	
	devices, err := manager.ListDevices(context.Background(), &core.ListDevicesHandlerReq{
		Token:  cookie.Value,
		AppEUI: appEUI.Bytes(),
	})
	if err != nil {
		//ctx.WithError(err).Fatal("Could not get device list")
		//*****CHANGE To No Devices found HTML
		ctx.Infof("Could not get device list: %s", err)
		//http.NotFound(rw, req)
		//return
		
	} else {
	
	// format device OTAA and ABP data into structs to be passed to page context for template
	for _, device := range devices.ABP {
		
		var flags string
		if (device.Flags & core.RelaxFcntCheck) != 0 {
			flags = "relax-fcnt"
		}
		//if flags == "" {
		//	flags = "-"
		//}
		
		devAddr := fmt.Sprintf("%X", device.DevAddr)
		nwkSKey := fmt.Sprintf("%X", device.NwkSKey)
		appSKey := fmt.Sprintf("%X", device.AppSKey)
		
		abpDev := &ABPDevice{
			DevAddr:  devAddr, 
			NwkSKey:  nwkSKey,
			AppSKey:  appSKey,
			FCntUp:   device.FCntUp,
			FCntDown: device.FCntDown,
			Flags:    flags,
			AppEUI:   appEUI.String(), 
		}
		
		abpSlice = append(abpSlice, abpDev)
		
	}
	
	for _, device := range devices.OTAA {
		
		devEUI := fmt.Sprintf("%X", device.DevEUI)
		devAddr := fmt.Sprintf("%X", device.DevAddr)
		nwkSKey := fmt.Sprintf("%X", device.NwkSKey)
		appSKey := fmt.Sprintf("%X", device.AppSKey)
		appKey := fmt.Sprintf("%X", device.AppKey)
		
		otaaDev := &OTAADevice{
			DevEUI:   devEUI,
			DevAddr:  devAddr, 
			NwkSKey:  nwkSKey,
			AppSKey:  appSKey,
			AppKey:   appKey,
			FCntUp:   device.FCntUp,
			FCntDown: device.FCntDown,
			AppEUI:   appEUI.String(),
		}
		
		otaaSlice = append(otaaSlice, otaaDev)
		
	}
	
	}
	//ctx.Infof("Found %d Over the air (ABP)", len(devices.OTAA))
	
	devList := &ListDevices{
		OTAA: otaaSlice,
		ABP: abpSlice,
	}
	
	
	pagecontext, err := getPageContext(req)
	if err != nil {
		fmt.Errorf("Failed to get page context" + err.Error())
	}
	pagecontext.Title = "Devices"
	pagecontext.Devices = devList
	pagecontext.SelectedAppEUI = appEUI.String()
	pagecontext.SelectedAppName = getAppName(cookie.Value, appEUI.String())
	//pagecontext.Devices = devices
	render(rw, "devices", pagecontext)
	
	
}

func protectedDeviceInfo(rw http.ResponseWriter, req *http.Request) {
	
	// Get app EUI 
	cookie, err := req.Cookie("Auth")
	if err != nil {
		fmt.Println("no cookie found")
		http.NotFound(rw, req)
		return
	}


	manager := util.GetHandlerManager(ctx)
	
	urlPart := req.URL.Path[len("/device/"):]

	urlSplit := strings.Split(urlPart, "/")


	appEUI, err := types.ParseAppEUI(urlSplit[0])
	if err != nil {
		ctx.Infof("Invalid AppEUI: %s", err)
		http.NotFound(rw, req)
		return
	}
	
	pagecontext, err := getPageContext(req)
	if err != nil {
		fmt.Errorf("Failed to get page context" + err.Error())
	}
	
	if req.Method == "GET" {
		
		// list devices
		devices, err := manager.ListDevices(context.Background(), &core.ListDevicesHandlerReq{
			Token:  cookie.Value,
			AppEUI: appEUI.Bytes(),
		})
		if err != nil {
			//ctx.WithError(err).Fatal("Could not get device list")
			ctx.Infof("Could not get device list: %s", err)
			http.NotFound(rw, req)
			return
		}
	
		pagecontext.Title = "Device Info"
		pagecontext.SelectedAppEUI = appEUI.String()
		pagecontext.SelectedAppName = getAppName(cookie.Value, appEUI.String())
	
	
		var abpSlice []*ABPDevice
		var otaaSlice []*OTAADevice
	
	
		if devEUI, err := types.ParseDevEUI(urlSplit[1]); err == nil {
			for _, device := range devices.OTAA {
				if bytes.Equal(device.DevEUI, devEUI.Bytes()) {
					// Matching OTAA found
				
					devEUI := fmt.Sprintf("%X", device.DevEUI)
					devAddr := fmt.Sprintf("%X", device.DevAddr)
					nwkSKey := fmt.Sprintf("%X", device.NwkSKey)
					appSKey := fmt.Sprintf("%X", device.AppSKey)
					appKey := fmt.Sprintf("%X", device.AppKey)
		
					otaaDev := &OTAADevice{
						DevEUI:   devEUI,
						DevAddr:  devAddr, 
						NwkSKey:  nwkSKey,
						AppSKey:  appSKey,
						AppKey:   appKey,
						FCntUp:   device.FCntUp,
						FCntDown: device.FCntDown,
						AppEUI:   urlSplit[0],
					}
		
					otaaSlice = append(otaaSlice, otaaDev)
				
					devList := &ListDevices{
						OTAA: otaaSlice,
						ABP: abpSlice,
					}
					pagecontext.Devices = devList
					render(rw, "otaadevice", pagecontext)
					return
				}
			}
		}
	
		if devAddr, err := types.ParseDevAddr(urlSplit[1]); err == nil {
			for _, device := range devices.ABP {
				if bytes.Equal(device.DevAddr, devAddr.Bytes()) {
				
					var flags string
					if (device.Flags & core.RelaxFcntCheck) != 0 {
						flags = "relax-fcnt"
					}
					//if flags == "" {
					//	flags = "-"
					//}
		
					devAddr := fmt.Sprintf("%X", device.DevAddr)
					nwkSKey := fmt.Sprintf("%X", device.NwkSKey)
					appSKey := fmt.Sprintf("%X", device.AppSKey)
		
					abpDev := &ABPDevice{
						DevAddr:  devAddr, 
						NwkSKey:  nwkSKey,
						AppSKey:  appSKey,
						FCntUp:   device.FCntUp,
						FCntDown: device.FCntDown,
						Flags:    flags,
						AppEUI:   urlSplit[0], 
					}
		
					abpSlice = append(abpSlice, abpDev)
				
					devList := &ListDevices{
						OTAA: otaaSlice,
						ABP: abpSlice,
					}
					pagecontext.Devices = devList
					render(rw, "abpdevice", pagecontext)
					return
				
				}
			}
		}
	
		render(rw, "notfound", pagecontext)
		
		
	} else {
		
		
		// Get required device details & Work out if Delete or Update
		
		req.ParseForm()
		
		update :=req.Form.Get("updatebutton")
		delete := req.Form.Get("deletebutton")
		cancel := req.Form.Get("cancelbutton")
		
		devAdr := req.Form.Get("DevAdr")
		devEui := req.Form.Get("DevEui")
		
		if  update == "Update" && delete == "" {
			// Update device - ABP or OTAA?
			
			if devAdr == "" && devEui != "" {
				// update OTAA
				ctx.Infof("Device EUI: %s", devEui)
				
				devEUI, err := types.ParseDevEUI(devEui)
				if err != nil {
					ctx.Infof("Invalid DevEUI: %s", err)
					pagecontext.Title = "Invalid DevEUI"
					render(rw, "error", pagecontext)
					return
				}

				var appKey types.AppKey
				appKey, err = types.ParseAppKey(req.Form.Get("AppKey"))
				if err != nil {
					ctx.Infof("Invalid AppKey: %s", err)
					pagecontext.Title = "Invalid AppKey"
					render(rw, "error", pagecontext)
					return
				}
				
				res, err := manager.UpsertOTAA(context.Background(), &core.UpsertOTAAHandlerReq{
					Token:  cookie.Value,
					AppEUI: appEUI.Bytes(),
					DevEUI: devEUI.Bytes(),
					AppKey: appKey.Bytes(),
				})
				if err != nil || res == nil {
					ctx.Infof("Could not register device: %s", err)
					pagecontext.Title = "Could not register device"
					render(rw, "error", pagecontext)
					return
				}
				
				ctx.Infof("Registered OTAA device")
				
				//redirect to device page
				devURL := "/devices/"
				devURL += appEUI.String()
				http.Redirect(rw, req, devURL, 307)
				return
				
				
				
			} else if devAdr != "" && devEui == "" {
				// update ABP
				ctx.Infof("Device address: %s", devAdr)
				
				var nwkSKey types.NwkSKey
				var appSKey types.AppSKey
				var devAddr types.DevAddr
				var err error
				
				devAddr, err = types.ParseDevAddr(devAdr)
				if err != nil {
					ctx.Infof("Invalid DevAddr: %s", err)
					pagecontext.Title = "Invalid DevAddr"
					render(rw, "error", pagecontext)
					return
				}
				
				nwkSKey, err = types.ParseNwkSKey(req.Form.Get("NwkSKey"))
				if err != nil {
					ctx.Infof("Invalid NwkSKey: %s", err)
					pagecontext.Title = "Invalid NwkSKey"
					render(rw, "error", pagecontext)
					return
				}
				appSKey, err = types.ParseAppSKey(req.Form.Get("AppSKey"))
				if err != nil {
					ctx.Infof("Invalid AppSKey: %s", err)
					pagecontext.Title = "Invalid AppSKey"
					render(rw, "error", pagecontext)
					return
				}
				
				var flags uint32
				flagValue := req.Form.Get("fcntcheckbox")
				if flagValue != "" {
					flags |= core.RelaxFcntCheck
					ctx.Warn("You are disabling frame counter checks. Your device is not protected against replay-attacks.")
				}
				
				res, err := manager.UpsertABP(context.Background(), &core.UpsertABPHandlerReq{
					Token:  cookie.Value,
					AppEUI: appEUI.Bytes(),
					DevAddr: devAddr.Bytes(),
					AppSKey: appSKey.Bytes(),
					NwkSKey: nwkSKey.Bytes(),
					Flags:   flags,
				})
				if err != nil || res == nil {
					ctx.Infof("Could not register device: %s", err)
					pagecontext.Title = "Could not register device"
					render(rw, "error", pagecontext)
					return
				}
				
				ctx.Infof("Registered personalized device")
			}
			
			//redirect to device page
			devURL := "/devices/"
			devURL += appEUI.String()
			http.Redirect(rw, req, devURL, 307)
			return
			
		} else if update == "" && delete == "Delete" {
			
			// Delete device - ABP or OTAA?
			
			if devAdr == "" && devEui != "" {
				// Delete OTAA
				ctx.Infof("Device EUI: %s", devEui)
				
				if devEUI, err := types.ParseDevEUI(devEui); err == nil {
					
					ctx = ctx.WithField("DevEUI", devEUI)
					_, err := manager.DeleteOTAA(context.Background(), &core.DeleteOTAAHandlerReq{
						Token:  cookie.Value,
						AppEUI: appEUI.Bytes(),
						DevEUI: devEUI.Bytes(),
					})
					if err != nil {
						ctx.Infof("Could not delete OTAA device")
						pagecontext.Title = "Could not delete OTAA device"
						render(rw, "error", pagecontext)
						return
					}
					
				} else {
					ctx.Infof("Invalid DevEUI: %s", err)
					pagecontext.Title = "Invalid DevEUI"
					render(rw, "error", pagecontext)
					return
				}
				
				//redirect to device page
				devURL := "/devices/"
				devURL += appEUI.String()
				http.Redirect(rw, req, devURL, 307)
				return
				
			} else if devAdr != "" && devEui == "" {
				// Delete ABP
				ctx.Infof("Device address: %s", devAdr)
				
				if devAddr, err := types.ParseDevAddr(devAdr); err == nil {
					ctx = ctx.WithField("DevAddr", devAddr)
					_, err := manager.DeleteABP(context.Background(), &core.DeleteABPHandlerReq{
						Token:   cookie.Value,
						AppEUI:  appEUI.Bytes(),
						DevAddr: devAddr.Bytes(),
					})
					if err != nil {
						ctx.Infof("Could not delete ABP device")
						pagecontext.Title = "Could not delete ABP device"
						render(rw, "error", pagecontext)
						return
					}
		
				} else {
					
					ctx.Infof("Invalid DevAddr: %s", err)
					pagecontext.Title = "Invalid DevAddr"
					render(rw, "error", pagecontext)
					return
					
				}
				
				//redirect to device page
				devURL := "/devices/"
				devURL += appEUI.String()
				http.Redirect(rw, req, devURL, 307)
				return
				
			}
				
		} else if update == "" && cancel == "Cancel" {
			
			//redirect to device page
			devURL := "/devices/"
			devURL += appEUI.String()
			http.Redirect(rw, req, devURL, 307)
			return
			
		}
		
		ctx.Infof("Update button value: %s", update)
		ctx.Infof("Delete button value: %s", delete)
			
		pagecontext.Title = "Device Info"
		render(rw, "notfound", pagecontext)
		
	}
	
}


func protectedAddABP(rw http.ResponseWriter, req *http.Request) {
	
	// Get app EUI 
	cookie, err := req.Cookie("Auth")
	if err != nil {
		fmt.Println("no cookie found")
		http.NotFound(rw, req)
		return
	}
	
	appEuiString := req.URL.Path[len("/addabp/"):]

	appEUI, err := types.ParseAppEUI(appEuiString)
	if err != nil {
		ctx.Infof("Invalid AppEUI: %s", err)
		http.NotFound(rw, req)
		return
	}
	
	pagecontext, err := getPageContext(req)
	if err != nil {
		fmt.Errorf("Failed to get page context" + err.Error())
	}
	
	if req.Method == "GET" {
		
		pagecontext.Title = "Add Device"
		pagecontext.SelectedAppEUI = appEUI.String()
		pagecontext.SelectedAppName = getAppName(cookie.Value, appEUI.String())
	
		render(rw, "addabp", pagecontext)
		return
		
	} else {
		
		
		// Get required device details & Work out if Add or Cancel
		
		req.ParseForm()
		
		add :=req.Form.Get("addbutton")
		cancel := req.Form.Get("cancelbutton")
		
		if  add == "Add" && cancel == "" {
			
			// Get auth
			cookie, err := req.Cookie("Auth")
			if err != nil {
				fmt.Println("no cookie found")
				http.NotFound(rw, req)
				return
			}
	
			
			// Add device - ABP
			
			var nwkSKey types.NwkSKey
			var appSKey types.AppSKey
			var devAddr types.DevAddr
			
			devAdr := req.Form.Get("DevAdr")
			
			devAddr, err = types.ParseDevAddr(devAdr)
			if err != nil {
				ctx.Infof("Invalid DevAddr: %s", err)
				pagecontext.Title = "Invalid DevAddr"
				render(rw, "error", pagecontext)
				return
			}
			
			nwkSKey, err = types.ParseNwkSKey(req.Form.Get("NwkSKey"))
			if err != nil {
				ctx.Infof("Invalid NwkSKey: %s", err)
				pagecontext.Title = "Invalid NwkSKey"
				render(rw, "error", pagecontext)
				return
			}
			appSKey, err = types.ParseAppSKey(req.Form.Get("AppSKey"))
			if err != nil {
				ctx.Infof("Invalid AppSKey: %s", err)
				pagecontext.Title = "Invalid AppSKey"
				render(rw, "error", pagecontext)
				return
			}
			
			var flags uint32
			flagValue := req.Form.Get("fcntcheckbox")
			if flagValue != "" {
				flags |= core.RelaxFcntCheck
				ctx.Warn("You are disabling frame counter checks. Your device is not protected against replay-attacks.")
			}
			

			manager := util.GetHandlerManager(ctx)
			
			res, err := manager.UpsertABP(context.Background(), &core.UpsertABPHandlerReq{
				Token:  cookie.Value,
				AppEUI: appEUI.Bytes(),
				DevAddr: devAddr.Bytes(),
				AppSKey: appSKey.Bytes(),
				NwkSKey: nwkSKey.Bytes(),
				Flags:   flags,
			})
			if err != nil || res == nil {
				ctx.Infof("Could not register device: %s", err)
				pagecontext.Title = "Could not register device"
				render(rw, "error", pagecontext)
				return
			}
			
			ctx.Infof("Registered personalized device")
			
			//redirect to device page
			devURL := "/devices/"
			devURL += appEUI.String()
			http.Redirect(rw, req, devURL, 307)
			return
			
		} else if add == "" && cancel == "Cancel" {
			
			//redirect to device page
			devURL := "/devices/"
			devURL += appEUI.String()
			http.Redirect(rw, req, devURL, 307)
			return
		}
			
		pagecontext.Title = "Device Info"
		render(rw, "notfound", pagecontext)
		
	}
	
}


func protectedAddOTAA(rw http.ResponseWriter, req *http.Request) {
	
	// Get app EUI 
	cookie, err := req.Cookie("Auth")
	if err != nil {
		fmt.Println("no cookie found")
		http.NotFound(rw, req)
		return
	}
	
	appEuiString := req.URL.Path[len("/addotaa/"):]

	appEUI, err := types.ParseAppEUI(appEuiString)
	if err != nil {
		ctx.Infof("Invalid AppEUI: %s", err)
		http.NotFound(rw, req)
		return
	}
	
	pagecontext, err := getPageContext(req)
	if err != nil {
		fmt.Errorf("Failed to get page context" + err.Error())
	}
	
	if req.Method == "GET" {
		
		pagecontext.Title = "Add Device"
		pagecontext.SelectedAppEUI = appEUI.String()
		pagecontext.SelectedAppName = getAppName(cookie.Value, appEUI.String())
		
		render(rw, "addotaa", pagecontext)
		return
		
	} else {
		
		
		// Get required device details & Work out if Add or Cancel
		
		req.ParseForm()
		
		add :=req.Form.Get("addbutton")
		cancel := req.Form.Get("cancelbutton")
		
		if  add == "Add" && cancel == "" {
			
			// Get auth
			cookie, err := req.Cookie("Auth")
			if err != nil {
				fmt.Println("no cookie found")
				http.NotFound(rw, req)
				return
			}
	
			devEui := req.Form.Get("DevEui")
			devEUI, err := types.ParseDevEUI(devEui)
			if err != nil {
				ctx.Infof("Invalid DevEUI: %s", err)
				pagecontext.Title = "Invalid DevEUI"
				render(rw, "error", pagecontext)
				return
			}

			var appKey types.AppKey
			appKey, err = types.ParseAppKey(req.Form.Get("AppKey"))
			if err != nil {
				ctx.Infof("Invalid AppKey: %s", err)
				pagecontext.Title = "Invalid AppKey"
				render(rw, "error", pagecontext)
				return
			}
			manager := util.GetHandlerManager(ctx)
			res, err := manager.UpsertOTAA(context.Background(), &core.UpsertOTAAHandlerReq{
				Token:  cookie.Value,
				AppEUI: appEUI.Bytes(),
				DevEUI: devEUI.Bytes(),
				AppKey: appKey.Bytes(),
			})
			if err != nil || res == nil {
				ctx.Infof("Could not register device: %s", err)
				pagecontext.Title = "Could not register device"
				render(rw, "error", pagecontext)
				return
			}
			
			ctx.Infof("Registered OTAA device")
			
			//redirect to device page
			devURL := "/devices/"
			devURL += appEUI.String()
			http.Redirect(rw, req, devURL, 307)
			return
			
			
		} else if add == "" && cancel == "Cancel" {
			
			//redirect to device page
			devURL := "/devices/"
			devURL += appEUI.String()
			http.Redirect(rw, req, devURL, 307)
			return
		}
			
		pagecontext.Title = "Device Info"
		render(rw, "notfound", pagecontext)
		
	}
	
}

func protectedUsers(rw http.ResponseWriter, req *http.Request) {
	
	//Get users via API
	cookie, err := req.Cookie("Auth")
	if err != nil {
		fmt.Println("no cookie found")
		http.NotFound(rw, req)
		return
	}

	// check AppEUI provided is owned by user
	users, err := util.GetUsers(cookie.Value, AUTH_URL)
	if err != nil {
		fmt.Errorf("Failed to get user list" + err.Error())
	}
	for _, user := range users {
		fmt.Printf("User found: %s", user.UserName)
	}

	pagecontext, err := getPageContext(req)
	if err != nil {
		fmt.Errorf("Failed to get page context" + err.Error())
	}
	pagecontext.Title = "Users"
	pagecontext.Users = users
	render(rw, "users", pagecontext)
	
}

func protectedAddUser(rw http.ResponseWriter, req *http.Request) {
	
	if req.Method == "GET" {
		
		pagecontext, err := getPageContext(req)
		if err != nil {
			fmt.Errorf("Failed to get page context" + err.Error())
		}
		
		pagecontext.Title = "Add User"
		render(rw, "adduser", pagecontext)
		return
		
	} else if req.Method == "POST" {
		
		req.ParseForm()
		
		firstName := req.Form.Get("firstname")
		lastName := req.Form.Get("lastname")
		userName := req.Form.Get("username")
		password := req.Form.Get("password")
		email :=   req.Form.Get("email")
		var scope string 
		
		fmt.Printf("User first name: %s\n", firstName)
		fmt.Printf("User last name: %s\n", lastName)
		fmt.Printf("Username: %s\n", userName)
		
		adminValue := req.Form.Get("admincheckbox")
		if adminValue == "admin" {
			scope = "profile,apps,admin"
		} else {
			scope ="profile,apps"
		}
		
		cookie, err := req.Cookie("Auth")
		if err != nil {
			fmt.Println("no cookie found")
			http.NotFound(rw, req)
			return
		}
		
		
		uri := fmt.Sprintf("%s/user", AUTH_URL)
		values := url.Values{
			"firstname": {firstName},
			"lastname": {lastName},
			"username": {userName},
			"password": {password},
			"email": {email},
			"scope": {scope},
		}
		authreq, err := util.NewRequestWithAuth(cookie.Value, "POST", uri, strings.NewReader(values.Encode()))
		if err != nil {
			ctx.Infof("Failed to create authenticated request: %s", err)
		}

		authreq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		client := &http.Client{}
		resp, err := client.Do(authreq)
		if err != nil {
			ctx.Infof("Failed to create user, error: %s", err)
		}
		if resp.StatusCode != http.StatusCreated {
			ctx.Infof("Failed to create user, response: %s", resp.Status)
		}

		ctx.Info("User created successfully")
		
		
		http.Redirect(rw, req, "/users", 307)
		return
	}

}

func protectedUser(rw http.ResponseWriter, req *http.Request) {
	
	userString := req.URL.Path[len("/user/"):]
	
	var userId int
	
	if v, err := strconv.Atoi(userString); err == nil {
		userId = v
	} else {
		fmt.Printf("Invalid or missing UserID %s\n", err)   
		http.Error(rw, "Server error, Invalid or missing UserID.", 500)    
		return
	}
	
	cookie, err := req.Cookie("Auth")
	if err != nil {
		fmt.Println("no cookie found")
		http.NotFound(rw, req)
		return
	}
	
	if req.Method == "GET" {
		
		// Get user to display and apps to determine which user is part of
		
		// check AppEUI provided is owned by user
		user, err := util.GetUser(cookie.Value, AUTH_URL, userString)
		if err != nil {
			fmt.Errorf("Failed to get user info" + err.Error())
		}
		
		apps, err2 := util.GetApplications(cookie.Value, AUTH_URL)
		if err2 != nil {
			fmt.Errorf("Failed to get application list" + err2.Error())
		}
		/*
		for _, app := range apps {
			if app.EUI.String() == appEui {
				appName = app.Name
			}
		}
		*/
		var users []*util.User
		
		if user.UserID == userId {
			
			var isAdmin bool = false
			
			scopes := strings.Split(user.Scope, ",")
			
		    for i := range scopes {
				if scopes[i] == "admin"{
					isAdmin = true
				}
			}
			
			user.Admin = isAdmin	
			users = append(users, user)
			
		}
		
		pagecontext, err := getPageContext(req)
		if err != nil {
			fmt.Errorf("Failed to get page context" + err.Error())
		}
		pagecontext.Title = "User Details - " + user.FirstName + " " + user.LastName
		pagecontext.Users = users
		pagecontext.Apps = apps
		render(rw, "user", pagecontext)
		
		return
		
	} else if req.Method == "POST" {
		
		req.ParseForm()
		
		firstName := req.Form.Get("firstname")
		lastName := req.Form.Get("lastname")
		userName := req.Form.Get("username")
		password := req.Form.Get("password")
		email :=   req.Form.Get("email")
		var scope string 
		
		fmt.Printf("User first name: %s\n", firstName)
		fmt.Printf("User last name: %s\n", lastName)
		fmt.Printf("Username: %s\n", userName)
		
		adminValue := req.Form.Get("admincheckbox")
		if adminValue == "admin" {
			scope = "profile,apps,admin"
		} else {
			scope ="profile,apps"
		}
		
		cookie, err := req.Cookie("Auth")
		if err != nil {
			fmt.Println("no cookie found")
			http.NotFound(rw, req)
			return
		}
		
		
		uri := fmt.Sprintf("%s/user/%s", AUTH_URL, userString)
		values := url.Values{
			"firstname": {firstName},
			"lastname": {lastName},
			"username": {userName},
			"password": {password},
			"email": {email},
			"scope": {scope},
		}
		authreq, err := util.NewRequestWithAuth(cookie.Value, "PUT", uri, strings.NewReader(values.Encode()))
		if err != nil {
			ctx.Infof("Failed to create authenticated request: %s", err)
		}

		authreq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		client := &http.Client{}
		resp, err := client.Do(authreq)
		if err != nil {
			ctx.Infof("Failed to update user, error: %s", err)
		}
		if resp.StatusCode != http.StatusOK {
			ctx.Infof("Failed to update user, response: %s", resp.Status)
		}

		ctx.Info("User updated successfully")
		
		
		http.Redirect(rw, req, "/users", 307)
		return
		
	}
}

func protectedDelUser(rw http.ResponseWriter, req *http.Request) {
	
	userString := req.URL.Path[len("/deluser/"):]
	
	cookie, err := req.Cookie("Auth")
	if err != nil {
		fmt.Println("no cookie found")
		http.NotFound(rw, req)
		return
	}
	
	uri := fmt.Sprintf("%s/user/%s", AUTH_URL, userString)
	
	authreq, err := util.NewRequestWithAuth(cookie.Value, "DELETE", uri, nil)
	if err != nil {
		ctx.Infof("Failed to create authenticated request: %s", err)
	}
	
	client := &http.Client{}
	resp, err := client.Do(authreq)
	if err != nil {
		ctx.Infof("Failed to delete user, error: %s", err)
	}
	if resp.StatusCode != http.StatusOK {
		ctx.Infof("Failed to delete user, response: %s", resp.Status)
	}

	ctx.Info("User deleted successfully")
	
	
	http.Redirect(rw, req, "/users", 307)
	return
	
}



func protectedUnlink(rw http.ResponseWriter, req *http.Request) {
	
	urlPart := req.URL.Path[len("/unlink/"):]

	urlSplit := strings.Split(urlPart, "/")
	
	appEUI, err := types.ParseAppEUI(urlSplit[0])
	if err != nil {
		ctx.Infof("Invalid AppEUI: %s", err)
		http.NotFound(rw, req)
		return
	}
	
	if len(urlSplit) == 2 {
		
		cookie, err := req.Cookie("Auth")
		if err != nil {
			fmt.Println("no cookie found")
			http.NotFound(rw, req)
			return
		}
		
		uri := fmt.Sprintf("%s/link/%s/%s", AUTH_URL, appEUI.String(), urlSplit[1])
	
		authreq, err := util.NewRequestWithAuth(cookie.Value, "DELETE", uri, nil)
		if err != nil {
			ctx.Infof("Failed to create authenticated request: %s", err)
		}
	
		client := &http.Client{}
		resp, err := client.Do(authreq)
		if err != nil {
			ctx.Infof("Failed to unlink user and application, error: %s", err)
		}
		if resp.StatusCode != http.StatusCreated {
			ctx.Infof("Failed to unlink user and application, response: %s", resp.Status)
		}

		ctx.Info("User and application unlinked successfully")
	
		userURL := "/user/"
		userURL += urlSplit[1]
		http.Redirect(rw, req, userURL, 307)
		return
		
		
	} else {
		
		fmt.Println("Incorrect url format")
		http.NotFound(rw, req)
		return
	}

	
}


func protectedLink(rw http.ResponseWriter, req *http.Request) {
	
	urlPart := req.URL.Path[len("/link/"):]

	urlSplit := strings.Split(urlPart, "/")
	
	appEUI, err := types.ParseAppEUI(urlSplit[0])
	if err != nil {
		ctx.Infof("Invalid AppEUI: %s", err)
		http.NotFound(rw, req)
		return
	}
	
	if len(urlSplit) == 2 {
		
		cookie, err := req.Cookie("Auth")
		if err != nil {
			fmt.Println("no cookie found")
			http.NotFound(rw, req)
			return
		}
		
		uri := fmt.Sprintf("%s/link/%s/%s", AUTH_URL, appEUI.String(), urlSplit[1])
	
		authreq, err := util.NewRequestWithAuth(cookie.Value, "POST", uri, nil)
		if err != nil {
			ctx.Infof("Failed to create authenticated request: %s", err)
		}
	
		client := &http.Client{}
		resp, err := client.Do(authreq)
		if err != nil {
			ctx.Infof("Failed to link user and application, error: %s", err)
		}
		if resp.StatusCode != http.StatusCreated {
			ctx.Infof("Failed to link user and application, response: %s", resp.Status)
		}

		ctx.Info("User and application linked successfully")
	
		userURL := "/user/"
		userURL += urlSplit[1]
		http.Redirect(rw, req, userURL, 307)
		return
		
		
	} else {
		
		fmt.Println("Incorrect url format")
		http.NotFound(rw, req)
		return
		
	}
	
}
