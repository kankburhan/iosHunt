package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"ioshunt/core"

	"github.com/spf13/cobra"
)

var sideloadCmd = &cobra.Command{
	Use:   "sideload [list|pair|install|uninstall|apps]",
	Short: "Deploy IPAs to non-jailbroken devices via libimobiledevice",
	Long: `Layered installer for non-JB iOS devices. Prefers ideviceinstaller
(libimobiledevice) with auto-fallback to ios-deploy and AltStore.

Subcommands:
  list                List devices visible to libimobiledevice
  pair                Pair the device (tap "Trust" on screen first)
  install <ipa>       Install an IPA (auto-finds re-signed if --ipa omitted)
  uninstall <bundle>  Remove app by bundle ID
  apps                List installed user apps`,
	Args: cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		action := args[0]
		udid, _ := cmd.Flags().GetString("device")
		ipa, _ := cmd.Flags().GetString("ipa")
		method, _ := cmd.Flags().GetString("method")
		bundleID, _ := cmd.Flags().GetString("bundle")
		launch, _ := cmd.Flags().GetBool("launch")

		switch action {
		case "list":
			devs, err := core.ListSideloadDevices()
			if err != nil {
				fmt.Println("[!]", err)
				os.Exit(1)
			}
			if len(devs) == 0 {
				fmt.Println("[*] No devices.")
				return
			}
			js, _ := json.MarshalIndent(devs, "", "  ")
			fmt.Println(string(js))

		case "pair":
			if err := core.PairDevice(udid); err != nil {
				fmt.Println("[!]", err)
				os.Exit(1)
			}
			fmt.Println("[+] Pair OK")

		case "install":
			if ipa == "" && len(args) >= 2 {
				ipa = args[1]
			}
			if ipa == "" {
				fmt.Println("[!] --ipa or positional path required")
				os.Exit(1)
			}
			res := core.Sideload(core.SideloadOptions{
				IPAPath:    ipa,
				BundleID:   bundleID,
				DeviceUDID: udid,
				Method:     method,
				Launch:     launch,
			})
			js, _ := json.MarshalIndent(res, "", "  ")
			fmt.Println(string(js))
			if !res.Success {
				os.Exit(1)
			}

		case "uninstall":
			if bundleID == "" && len(args) >= 2 {
				bundleID = args[1]
			}
			if bundleID == "" {
				fmt.Println("[!] bundle ID required")
				os.Exit(1)
			}
			if err := core.UninstallApp(udid, bundleID); err != nil {
				fmt.Println("[!]", err)
				os.Exit(1)
			}
			fmt.Println("[+] Uninstalled", bundleID)

		case "apps":
			bundles, err := core.ListInstalledApps(udid)
			if err != nil {
				fmt.Println("[!]", err)
				os.Exit(1)
			}
			fmt.Printf("[*] %d apps:\n", len(bundles))
			for _, b := range bundles {
				fmt.Println(" -", b)
			}

		default:
			cmd.Help()
		}
	},
}

func init() {
	rootCmd.AddCommand(sideloadCmd)
	sideloadCmd.Flags().StringP("device", "u", "", "Device UDID (auto-pick if empty)")
	sideloadCmd.Flags().StringP("ipa", "i", "", "IPA path (for install)")
	sideloadCmd.Flags().StringP("bundle", "b", "", "Bundle ID")
	sideloadCmd.Flags().StringP("method", "m", "auto", "auto|idevice|ios-deploy|altstore")
	sideloadCmd.Flags().Bool("launch", false, "Launch after install")
}
