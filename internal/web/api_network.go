package web

import (
	"fmt"
	"ir-toolkit/internal/store"
	"net/http"
	"strconv"
	"strings"
)

type NetworkListItem struct {
	ID string `json:"id"`

	PID uint32 `json:"pid"`

	ProcessName string `json:"process_name,omitempty"`

	ProcessPath string `json:"process_path,omitempty"`

	User string `json:"user,omitempty"`

	AuthenticationID string `json:"authentication_id,omitempty"`

	Protocol string `json:"protocol"`

	Family string `json:"family,omitempty"`

	LocalAddress string `json:"local_address"`

	LocalPort uint32 `json:"local_port"`

	RemoteAddress string `json:"remote_address,omitempty"`

	RemotePort uint32 `json:"remote_port,omitempty"`

	State string `json:"state,omitempty"`

	Kind string `json:"kind"`

	External bool `json:"external"`
}

type NetworkListResponse struct {
	Total uint32 `json:"total"`

	Offset uint32 `json:"offset"`

	Limit uint32 `json:"limit"`

	HasMore bool `json:"has_more"`

	Connections []NetworkListItem `json:"connections"`
}

type NetworkDetailResponse struct {
	Connection NetworkListItem `json:"connection"`
}

func (s *Server) loadNetworkListItems() (
	[]NetworkListItem,
	error,
) {

	items,
		err :=
		s.store.NetworkItems()

	if err != nil {

		return nil,
			fmt.Errorf(
				"load network analysis: %w",
				err,
			)
	}

	webItems :=
		make(
			[]NetworkListItem,
			0,
			len(items),
		)

	for _, item := range items {

		webItems =
			append(
				webItems,
				networkListItemFromQueryItem(
					item,
				),
			)
	}

	return webItems,
		nil
}

func networkListItemFromQueryItem(
	item store.NetworkQueryItem,
) NetworkListItem {

	return NetworkListItem{
		ID: item.ID,

		PID: item.PID,

		ProcessName: item.ProcessName,

		ProcessPath: item.ProcessPath,

		User: item.User,

		AuthenticationID: item.AuthenticationID,

		Protocol: item.Protocol,

		Family: item.Family,

		LocalAddress: item.LocalAddress,

		LocalPort: item.LocalPort,

		RemoteAddress: item.RemoteAddress,

		RemotePort: item.RemotePort,

		State: item.State,

		Kind: item.Kind,

		External: item.External,
	}
}

func (s *Server) handleNetwork(
	writer http.ResponseWriter,
	request *http.Request,
) {

	values :=
		request.URL.Query()

	query :=
		strings.TrimSpace(
			values.Get("q"),
		)

	ip :=
		strings.TrimSpace(
			values.Get("ip"),
		)

	state :=
		strings.TrimSpace(
			values.Get("state"),
		)

	var pid uint32

	if raw :=
		strings.TrimSpace(
			values.Get("pid"),
		); raw != "" {

		value,
			err :=
			strconv.ParseUint(
				raw,
				10,
				32,
			)

		if err != nil {

			writeAPIError(
				writer,
				http.StatusBadRequest,
				"invalid pid",
			)

			return
		}

		pid =
			uint32(value)
	}

	var external *bool

	if raw :=
		strings.TrimSpace(
			strings.ToLower(
				values.Get("external"),
			),
		); raw != "" {

		switch raw {

		case "true", "1", "yes":

			value :=
				true

			external =
				&value

		case "false", "0", "no":

			value :=
				false

			external =
				&value

		default:

			writeAPIError(
				writer,
				http.StatusBadRequest,
				"invalid external filter",
			)

			return
		}
	}

	offset,
		limit :=
		parseQueryPagination(
			values,
		)

	result,
		err :=
		s.store.QueryNetwork(
			store.NetworkQueryOptions{
				Query: query,

				PID: pid,

				IP: ip,

				State: state,

				External: external,

				Page: store.QueryPageOptions{
					Offset: offset,

					Limit: limit,
				},
			},
		)

	if err != nil {

		writeAPIError(
			writer,
			http.StatusInternalServerError,
			fmt.Sprintf(
				"query network analysis: %v",
				err,
			),
		)

		return
	}

	connections :=
		make(
			[]NetworkListItem,
			0,
			len(result.Items),
		)

	for _, item := range result.Items {

		connections =
			append(
				connections,
				networkListItemFromQueryItem(
					item,
				),
			)
	}

	writeJSON(
		writer,
		http.StatusOK,
		NetworkListResponse{
			Total: result.Total,

			Offset: uint32(
				result.Page.Offset,
			),

			Limit: uint32(
				result.Page.Limit,
			),

			HasMore: result.Page.HasMore,

			Connections: connections,
		},
	)
}

func (s *Server) handleNetworkDetail(
	writer http.ResponseWriter,
	request *http.Request,
) {

	id :=
		strings.TrimSpace(
			request.URL.Query().
				Get("id"),
		)

	if id == "" {

		writeAPIError(
			writer,
			http.StatusBadRequest,
			"id is required",
		)

		return
	}

	item,
		found,
		err :=
		s.store.NetworkItemByID(
			id,
		)

	if err != nil {

		writeAPIError(
			writer,
			http.StatusInternalServerError,
			fmt.Sprintf(
				"load network analysis: %v",
				err,
			),
		)

		return
	}

	if !found {

		writeAPIError(
			writer,
			http.StatusNotFound,
			"network evidence not found",
		)

		return
	}

	webItem :=
		networkListItemFromQueryItem(
			item,
		)

	writeJSON(
		writer,
		http.StatusOK,
		NetworkDetailResponse{
			Connection: webItem,
		},
	)
}

func webNetworkConnectionFromStore(
	connection store.NetworkConnectionRecord,
) webNetworkConnection {

	return webNetworkConnection{
		PID: connection.PID,

		ProcessName: connection.ProcessName,

		ProcessPath: connection.ProcessPath,

		Protocol: connection.Protocol,

		Family: connection.Family,

		LocalAddress: connection.LocalAddress,

		LocalPort: connection.LocalPort,

		RemoteAddress: connection.RemoteAddress,

		RemotePort: connection.RemotePort,

		State: connection.State,
	}
}

func webProcessNetworkAnalysisFromStore(
	process store.ProcessNetworkRecord,
) webProcessNetworkAnalysis {

	connections :=
		make(
			[]webNetworkConnection,
			0,
			len(process.Connections),
		)

	for _, connection := range process.Connections {

		connections =
			append(
				connections,
				webNetworkConnectionFromStore(
					connection,
				),
			)
	}

	listeners :=
		make(
			[]webNetworkConnection,
			0,
			len(process.Listeners),
		)

	for _, connection := range process.Listeners {

		listeners =
			append(
				listeners,
				webNetworkConnectionFromStore(
					connection,
				),
			)
	}

	externalConnections :=
		make(
			[]webNetworkConnection,
			0,
			len(process.ExternalConnections),
		)

	for _, connection := range process.ExternalConnections {

		externalConnections =
			append(
				externalConnections,
				webNetworkConnectionFromStore(
					connection,
				),
			)
	}

	return webProcessNetworkAnalysis{
		PID: process.PID,

		ProcessName: process.ProcessName,

		ProcessPath: process.ProcessPath,

		User: process.User,

		SessionID: process.SessionID,

		AuthenticationID: process.AuthenticationID,

		IntegrityLevel: process.IntegrityLevel,

		StartTime: process.StartTime,

		Connections: connections,

		Listeners: listeners,

		ExternalConnections: externalConnections,
	}
}

func webNetworkAnalysisFromStore(
	analysis *store.NetworkAnalysisRecord,
) *webNetworkAnalysis {

	if analysis == nil {
		return nil
	}

	result :=
		&webNetworkAnalysis{
			Processes: make(
				[]webProcessNetworkAnalysis,
				0,
				len(analysis.Processes),
			),
		}

	for _, process := range analysis.Processes {

		result.Processes =
			append(
				result.Processes,
				webProcessNetworkAnalysisFromStore(
					process,
				),
			)
	}

	return result
}
