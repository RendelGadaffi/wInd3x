package main

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/spf13/cobra"

	"github.com/freemyipod/wInd3x/pkg/exploit/loader"
)

var bootForce bool

var bootCmd = &cobra.Command{
	Use:   "boot [itb path]",
	Short: "Stream a FIT image to a Nano 7G in DFU and boot Linux from DRAM",
	Long: `Streams a FIT image (kernel + dtb + initramfs) into DRAM via the stage-1
DFU loader installed through the S5Late exploit chain, then boots the Linux
zImage with the device tree. RAM-only: a reboot returns to the stock OS.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		app, err := newDFU()
		if err != nil {
			return err
		}
		defer app.Close()

		ep, ok := app.Ep.(loader.Parameters)
		if !ok {
			return fmt.Errorf("device %s is not a Nano 7G: stage-1 boot is N31-only", app.Desc.Kind)
		}

		path := args[0]
		slog.Info("Reading image", "path", path)
		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("failed to read image: %w", err)
		}
		slog.Info("Image loaded", "bytes", len(data))

		// app.PrepareUSB (newDFU) already ran the S5Late stage-1 on N7G.
		blockno, err := loader.Trigger(app.Usb, ep, bootForce)
		if err != nil {
			return fmt.Errorf("installing stage-1 loader: %w", err)
		}

		slog.Info("Streaming FIT image...")
		last := -1
		err = loader.SendFit(app.Usb, data, blockno, func(p float32) {
			pct := int(p * 100)
			if pct != last && pct%5 == 0 {
				last = pct
				slog.Info("Streaming", "percent", pct)
			}
		})
		if err != nil {
			return fmt.Errorf("streaming image: %w", err)
		}

		slog.Info("Done — the nano should now boot Linux (serial console: 115200 on ttySAC0)")
		return nil
	},
}

func init() {
	bootCmd.Flags().BoolVar(&bootForce, "force", false, "re-install the loader even if the device reports it is armed")
}
