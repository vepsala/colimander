# `make app` builds everything, restarts the daemon on the new build and opens the app.
.PHONY: build app

BUNDLE := bin/Colimander.app

build:
	go build -o bin/colimander .
	CGO_LDFLAGS="-framework UniformTypeIdentifiers" go build -tags desktop,production -o bin/colimander-app ./cmd/colimander-app 2>/dev/null
	rm -rf $(BUNDLE) bin/icon.iconset
	mkdir -p $(BUNDLE)/Contents/MacOS $(BUNDLE)/Contents/Resources bin/icon.iconset
	for s in 16 32 128 256 512; do \
		sips -z $$s $$s assets/icon.png --out bin/icon.iconset/icon_$${s}x$${s}.png >/dev/null; \
		sips -z $$((s*2)) $$((s*2)) assets/icon.png --out bin/icon.iconset/icon_$${s}x$${s}@2x.png >/dev/null; \
	done
	iconutil -c icns bin/icon.iconset -o $(BUNDLE)/Contents/Resources/icon.icns
	rm -rf bin/icon.iconset
	cp assets/Info.plist $(BUNDLE)/Contents/Info.plist
	mv bin/colimander-app $(BUNDLE)/Contents/MacOS/colimander-app

app: build
	bin/colimander broker stop
	bin/colimander broker start
	open $(BUNDLE)
