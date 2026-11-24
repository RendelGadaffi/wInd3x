package main

import (
	"bytes"
	"fmt"
	"log/slog"
	"os"

	"github.com/spf13/cobra"

	"github.com/freemyipod/wInd3x/pkg/devices"
	"github.com/freemyipod/wInd3x/pkg/dfu"
	"github.com/freemyipod/wInd3x/pkg/exploit/haxeddfu"
	"github.com/freemyipod/wInd3x/pkg/exploit/loader"
	"github.com/freemyipod/wInd3x/pkg/image"
)

var runCmd = &cobra.Command{
	Use:   "run [dfu image path]",
	Short: "Run a DFU image on a device",
	Long:  "Run a DFU image (signed/encrypted or unsigned) on a connected device, starting haxed dfu mode first if necessary.",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		app, err := newDFU()
		if err != nil {
			return err
		}
		defer app.Close()

		if err := haxeddfu.Trigger(app.Usb, app.Ep, false); err != nil {
			return fmt.Errorf("failed to run wInd3x exploit: %w", err)
		}

		path := args[0]
		slog.Info("Uploading...", "path", path)
		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("Failed to read image: %w", err)
		}

		_, err = image.Read(bytes.NewReader(data))
		switch {
		case err == nil:
		case err == image.ErrNotImage1, len(data) < 0x400:
			slog.Info("Given firmware file is not IMG1, packing into one...")
			entry := uint32(0)
			if app.Desc.Kind == devices.Nano7 || app.Desc.Kind == devices.Nano7Late {
				// Nano 7G: big-image boot. Append the stage-1 loader after the
				// FIT and jump to it at manifest (entry is relative to the
				// IMG1 body base; the loader parses the FIT in DRAM and boots
				// the Linux kernel with its dtb).
				code, lentry, lerr := loader.Build(data)
				if lerr != nil {
					return fmt.Errorf("building stage-1 loader: %w", lerr)
				}
				pad := (16 - len(data)%16) % 16
				body := make([]byte, 0, len(data)+pad+len(code))
				body = append(body, data...)
				body = append(body, make([]byte, pad)...)
				body = append(body, code...)
				data = body
				// Build's entry is relative to the IMG1 base (it already
				// includes the 0x400 header offset).
				entry = lentry
				slog.Info("Stage-1 loader appended", "loaderBytes", len(code), "entry", fmt.Sprintf("0x%x", entry))
			}
			data, err = image.MakeUnsigned(app.Desc.Kind, entry, data)
			if err != nil {
				return err
			}
		default:
			return err
		}

		if err := dfu.Clean(app.Usb); err != nil {
			return fmt.Errorf("Failed to clean: %w", err)
		}
		if err := dfu.SendImage(app.Usb, data, app.Desc.Kind.DFUVersion()); err != nil {
			return fmt.Errorf("Failed to send image: %w", err)
		}
		slog.Info("Image sent.")

		return nil
	},
}
