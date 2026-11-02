//go:build desktop

// Command colimander-app is the Mac interface to the Colimander daemon.
//
//	CGO_LDFLAGS="-framework UniformTypeIdentifiers" go build -tags desktop,production ./cmd/colimander-app
package main

import (
	"log"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
	"github.com/wailsapp/wails/v2/pkg/options/mac"

	"github.com/vepsala/colimander/internal/appui"
	"github.com/vepsala/colimander/internal/broker"
)

func main() {
	err := wails.Run(&options.App{
		Title:       "Colimander",
		Width:       1000,
		Height:      680,
		MinWidth:    640,
		MinHeight:   400,
		AssetServer: &assetserver.Options{Handler: appui.Handler(broker.ControlSocket(), broker.DBAdminSocket())},
		Mac: &mac.Options{
			TitleBar: mac.TitleBarHiddenInset(),
		},
	})
	if err != nil {
		log.Fatal(err)
	}
}
