//go:build desktop

// Command colimander-app is the Mac interface to the Colimander daemon.
//
//	CGO_LDFLAGS="-framework UniformTypeIdentifiers" go build -tags desktop,production ./cmd/colimander-app
package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
	"github.com/wailsapp/wails/v2/pkg/options/mac"
	"github.com/wailsapp/wails/v2/pkg/runtime"

	"github.com/vepsala/colimander/internal/appui"
	"github.com/vepsala/colimander/internal/broker"
)

// withNative adds what the page can't do itself: a native dialog, and a clipboard
// write that still works after an awaited request has used up the click.
func withNative(ui http.Handler, ctx *context.Context) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/", ui)
	mux.HandleFunc("POST /native/pick-folder", func(w http.ResponseWriter, r *http.Request) {
		home, _ := os.UserHomeDir()
		path, err := runtime.OpenDirectoryDialog(*ctx, runtime.OpenDialogOptions{
			Title: "Choose a folder to import", DefaultDirectory: home, CanCreateDirectories: false,
		})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"path": path})
	})
	mux.Handle("POST /native/copy", appui.CopyHandler(
		func(text string) error { return runtime.ClipboardSetText(*ctx, text) },
		func() (string, error) { return runtime.ClipboardGetText(*ctx) },
	))
	return mux
}

func main() {
	appCtx := context.Background()
	err := wails.Run(&options.App{
		Title:       "Colimander",
		Width:       1000,
		Height:      680,
		MinWidth:    640,
		MinHeight:   400,
		AssetServer: &assetserver.Options{Handler: withNative(appui.Handler(broker.ControlSocket(), broker.DBAdminSocket()), &appCtx)},
		OnStartup:   func(ctx context.Context) { appCtx = ctx },
		Mac: &mac.Options{
			TitleBar: mac.TitleBarHiddenInset(),
		},
	})
	if err != nil {
		log.Fatal(err)
	}
}
