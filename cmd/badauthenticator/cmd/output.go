package cmd

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/spf13/cobra"
)

const (
	outputFormatJSON    = "json"
	outputFormatDecoded = "decoded"
)

func addOutputFlags(cmd *cobra.Command) {
	cmd.Flags().String("format", outputFormatJSON, "Output format: json or decoded")
	cmd.Flags().Bool("human-readable", false, "Write decoded human-readable details to stderr while keeping stdout as JSON")
}

func writeCommandOutput(cmd *cobra.Command, standard any, decoded any) error {
	format, _ := cmd.Flags().GetString("format")
	humanReadable, _ := cmd.Flags().GetBool("human-readable")

	switch format {
	case outputFormatJSON:
		if err := writeIndentedJSON(cmd.OutOrStdout(), standard); err != nil {
			return err
		}
		if humanReadable {
			if _, err := fmt.Fprintln(cmd.ErrOrStderr(), "\n--- Human Readable Output ---"); err != nil {
				return err
			}
			return writeIndentedJSON(cmd.ErrOrStderr(), decoded)
		}
		return nil
	case outputFormatDecoded:
		return writeIndentedJSON(cmd.OutOrStdout(), decoded)
	default:
		return fmt.Errorf("unknown output format %q (valid: json, decoded)", format)
	}
}

func writeIndentedJSON(w io.Writer, v any) error {
	jsonBytes, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal output to JSON: %w", err)
	}
	_, err = fmt.Fprintln(w, string(jsonBytes))
	return err
}
