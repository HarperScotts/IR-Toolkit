package analyzer

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	"ir-toolkit/internal/model"
)

type powerShellFragment struct {
	Event model.PowerShellEvent
}

func rebuildPowerShellScriptBlocks(
	events []model.PowerShellEvent,
) []model.PowerShellScriptBlock {

	grouped :=
		make(
			map[string][]powerShellFragment,
		)

	/*
		ScriptBlockId 理论上应该存在。

		但为了避免丢掉没有 ScriptBlockId 的 4104，
		给它构造一个退化分组键。
	*/
	for index, event := range events {

		if event.EventID != 4104 {
			continue
		}

		key :=
			strings.TrimSpace(
				event.ScriptBlockID,
			)

		if key == "" {

			key =
				fmt.Sprintf(
					"no-script-block-id-%d-%d",
					event.Timestamp.UnixNano(),
					index,
				)
		}

		grouped[key] =
			append(
				grouped[key],
				powerShellFragment{
					Event: event,
				},
			)
	}

	result :=
		make(
			[]model.PowerShellScriptBlock,
			0,
			len(grouped),
		)

	for key, fragments := range grouped {

		sort.SliceStable(
			fragments,
			func(i, j int) bool {

				left :=
					fragments[i].
						Event.
						MessageNumber

				right :=
					fragments[j].
						Event.
						MessageNumber

				/*
					MessageNumber 为 0 时，
					回退 Timestamp。
				*/
				if left == 0 ||
					right == 0 {

					return fragments[i].
						Event.
						Timestamp.
						Before(
							fragments[j].
								Event.
								Timestamp,
						)
				}

				return left < right
			},
		)

		first :=
			fragments[0].
				Event

		last :=
			fragments[len(fragments)-1].
				Event

		builder :=
			strings.Builder{}

		var expectedTotal uint32

		seenNumbers :=
			make(
				map[uint32]struct{},
			)

		for _, fragment := range fragments {

			event :=
				fragment.Event

			if expectedTotal == 0 &&
				event.MessageTotal > 0 {

				expectedTotal =
					event.MessageTotal
			}

			if event.MessageNumber > 0 {

				seenNumbers[event.MessageNumber] =
					struct{}{}
			}

			builder.WriteString(
				event.ScriptBlockText,
			)
		}

		text :=
			builder.String()

		complete := true

		if expectedTotal > 0 {

			complete =
				uint32(
					len(seenNumbers),
				) ==
					expectedTotal
		}

		hash :=
			sha256.Sum256(
				[]byte(text),
			)

		block :=
			model.PowerShellScriptBlock{
				ID: "powershell-script:" +
					sanitizeFindingID(
						key,
					),

				ScriptBlockID: first.ScriptBlockID,

				Timestamp: first.Timestamp,

				LastTimestamp: last.Timestamp,

				ProcessID: first.ProcessID,

				Path: first.Path,

				MessageTotal: expectedTotal,

				FragmentCount: uint32(
					len(fragments),
				),

				Complete: complete,

				ScriptText: text,

				ScriptSHA256: hex.EncodeToString(
					hash[:],
				),
			}

		result =
			append(
				result,
				block,
			)
	}

	sort.Slice(
		result,
		func(i, j int) bool {

			return result[i].
				Timestamp.
				Before(
					result[j].
						Timestamp,
				)
		},
	)

	return result
}
