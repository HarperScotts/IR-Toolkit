//go:build windows

package windows

import (
	"context"
	"fmt"
	"runtime"
	"strings"

	ole "github.com/go-ole/go-ole"
	"github.com/go-ole/go-ole/oleutil"

	"ir-toolkit/internal/model"
)

type securityCenterProduct struct {
	DisplayName string

	ProductState uint32

	PathToSignedProductExe string

	PathToSignedReportingExe string

	InstanceGUID string
}

func discoverSecurityCenterProviders(
	ctx context.Context,
) (
	[]model.SecurityProvider,
	[]string,
) {

	result :=
		make(
			[]model.SecurityProvider,
			0,
		)

	warnings :=
		make(
			[]string,
			0,
		)

	classes :=
		[]struct {
			ClassName string

			Type string
		}{
			{
				ClassName: "AntiVirusProduct",

				Type: "antivirus",
			},
			{
				ClassName: "AntiSpywareProduct",

				Type: "antispyware",
			},
			{
				ClassName: "FirewallProduct",

				Type: "firewall",
			},
		}

	for _, item := range classes {

		select {

		case <-ctx.Done():

			return mergeSecurityProviders(
					result,
				),
				append(
					warnings,
					ctx.Err().Error(),
				)

		default:
		}

		products, err :=
			querySecurityCenterClassCOM(
				ctx,
				item.ClassName,
			)

		if err != nil {

			warnings =
				append(
					warnings,
					fmt.Sprintf(
						"%s: %v",
						item.ClassName,
						err,
					),
				)

			continue
		}

		for _, product := range products {

			result =
				append(
					result,

					model.SecurityProvider{
						ID: sanitizeSecurityProviderID(
							product.InstanceGUID,
							product.DisplayName,
						),

						Name: product.DisplayName,

						Type: item.Type,

						ProductState: product.ProductState,

						ProductStateHex: fmt.Sprintf(
							"0x%06x",
							product.ProductState,
						),

						ProductExecutable: product.PathToSignedProductExe,

						ReportingExecutable: product.PathToSignedReportingExe,

						Registered: true,

						Source: "windows_security_center",
					},
				)
		}
	}

	return mergeSecurityProviders(
			result,
		),
		warnings
}

func querySecurityCenterClassCOM(
	ctx context.Context,
	className string,
) (
	[]securityCenterProduct,
	error,
) {

	/*
		COM initialization is bound to the current OS thread.

		Go goroutines can migrate between threads, so lock this
		goroutine for the complete COM operation.
	*/
	runtime.LockOSThread()

	defer runtime.UnlockOSThread()

	initialized, err :=
		initializeCOMForWMI()

	if err != nil {
		return nil, err
	}

	if initialized {
		defer ole.CoUninitialize()
	}

	select {

	case <-ctx.Done():
		return nil, ctx.Err()

	default:
	}

	locatorUnknown, err :=
		oleutil.CreateObject(
			"WbemScripting.SWbemLocator",
		)

	if err != nil {

		return nil,
			fmt.Errorf(
				"create SWbemLocator: %w",
				err,
			)
	}

	if locatorUnknown == nil {

		return nil,
			fmt.Errorf(
				"create SWbemLocator returned nil object",
			)
	}

	defer locatorUnknown.Release()

	locator, err :=
		locatorUnknown.QueryInterface(
			ole.IID_IDispatch,
		)

	if err != nil {

		return nil,
			fmt.Errorf(
				"query SWbemLocator IDispatch: %w",
				err,
			)
	}

	if locator == nil {

		return nil,
			fmt.Errorf(
				"SWbemLocator IDispatch is nil",
			)
	}

	defer locator.Release()

	/*
		Connect to the local Windows Security Center namespace.

		Using "." explicitly means local computer.
	*/
	servicesVariant, err :=
		oleutil.CallMethod(
			locator,
			"ConnectServer",
			".",
			`root\SecurityCenter2`,
		)

	if err != nil {

		return nil,
			fmt.Errorf(
				"connect root\\SecurityCenter2: %w",
				err,
			)
	}

	defer servicesVariant.Clear()

	services :=
		servicesVariant.ToIDispatch()

	if services == nil {

		return nil,
			fmt.Errorf(
				"SecurityCenter2 services interface is nil",
			)
	}

	/*
		Do NOT Release services separately here.

		The VARIANT owns the reference and servicesVariant.Clear()
		releases it.
	*/

	query :=
		fmt.Sprintf(
			`SELECT displayName, productState, pathToSignedProductExe, pathToSignedReportingExe, instanceGuid FROM %s`,
			className,
		)

	resultVariant, err :=
		oleutil.CallMethod(
			services,
			"ExecQuery",
			query,
		)

	if err != nil {

		return nil,
			fmt.Errorf(
				"ExecQuery %s: %w",
				className,
				err,
			)
	}

	defer resultVariant.Clear()

	resultSet :=
		resultVariant.ToIDispatch()

	if resultSet == nil {

		return nil,
			fmt.Errorf(
				"WMI result set for %s is nil",
				className,
			)
	}

	return enumerateSecurityCenterProducts(
		ctx,
		resultSet,
	)
}

func initializeCOMForWMI() (
	bool,
	error,
) {

	err :=
		ole.CoInitializeEx(
			0,
			ole.COINIT_MULTITHREADED,
		)

	if err == nil {
		return true, nil
	}

	oleErr, ok :=
		err.(*ole.OleError)

	if !ok {

		return false,
			fmt.Errorf(
				"CoInitializeEx: %w",
				err,
			)
	}

	switch oleErr.Code() {

	case ole.S_OK:

		return true, nil

	case 0x00000001:
		/*
			S_FALSE.

			COM was already initialized on this thread.
			The successful CoInitializeEx still needs a matching
			CoUninitialize.
		*/
		return true, nil

	case 0x80010106:
		/*
			RPC_E_CHANGED_MODE.

			The thread already has a different COM apartment model.
			COM is usable, but we must not call CoUninitialize for
			this failed CoInitializeEx call.
		*/
		return false, nil

	default:

		return false,
			fmt.Errorf(
				"CoInitializeEx failed: %#x: %w",
				oleErr.Code(),
				err,
			)
	}
}

func enumerateSecurityCenterProducts(
	ctx context.Context,
	resultSet *ole.IDispatch,
) (
	[]securityCenterProduct,
	error,
) {

	result :=
		make(
			[]securityCenterProduct,
			0,
		)

	// --------------------------------------------------
	// SWbemObjectSet.Count
	// --------------------------------------------------

	countVariant, err :=
		oleutil.GetProperty(
			resultSet,
			"Count",
		)

	if err != nil {

		return nil,
			fmt.Errorf(
				"get SecurityCenter2 result count: %w",
				err,
			)
	}

	if countVariant == nil {

		return nil,
			fmt.Errorf(
				"SecurityCenter2 Count returned nil",
			)
	}

	count :=
		variantToInt(
			countVariant,
		)

	countVariant.Clear()

	if count <= 0 {
		return result, nil
	}

	result =
		make(
			[]securityCenterProduct,
			0,
			count,
		)

	// --------------------------------------------------
	// SWbemObjectSet.ItemIndex(i)
	// --------------------------------------------------

	for index := 0; index < count; index++ {

		select {

		case <-ctx.Done():

			return result,
				ctx.Err()

		default:
		}

		itemVariant, err :=
			oleutil.CallMethod(
				resultSet,
				"ItemIndex",
				index,
			)

		if err != nil {

			return result,
				fmt.Errorf(
					"SecurityCenter2 ItemIndex(%d): %w",
					index,
					err,
				)
		}

		if itemVariant == nil {
			continue
		}

		item :=
			itemVariant.ToIDispatch()

		if item == nil {

			itemVariant.Clear()

			continue
		}

		product :=
			securityCenterProduct{
				DisplayName: getWMIStringProperty(
					item,
					"displayName",
				),

				ProductState: getWMIUint32Property(
					item,
					"productState",
				),

				PathToSignedProductExe: getWMIStringProperty(
					item,
					"pathToSignedProductExe",
				),

				PathToSignedReportingExe: getWMIStringProperty(
					item,
					"pathToSignedReportingExe",
				),

				InstanceGUID: getWMIStringProperty(
					item,
					"instanceGuid",
				),
			}

		/*
			itemVariant owns the COM reference returned
			by ItemIndex().
		*/
		itemVariant.Clear()

		if strings.TrimSpace(
			product.DisplayName,
		) == "" {

			continue
		}

		result =
			append(
				result,
				product,
			)
	}

	return result, nil
}

func getWMIStringProperty(
	object *ole.IDispatch,
	name string,
) string {

	value, err :=
		oleutil.GetProperty(
			object,
			name,
		)

	if err != nil ||
		value == nil {

		return ""
	}

	defer value.Clear()

	raw :=
		value.Value()

	if raw == nil {
		return ""
	}

	switch typed :=
		raw.(type) {

	case string:

		return typed

	default:

		return fmt.Sprint(
			typed,
		)
	}
}

func getWMIUint32Property(
	object *ole.IDispatch,
	name string,
) uint32 {

	value, err :=
		oleutil.GetProperty(
			object,
			name,
		)

	if err != nil ||
		value == nil {

		return 0
	}

	defer value.Clear()

	switch typed :=
		value.Value().(type) {

	case uint8:

		return uint32(
			typed,
		)

	case int8:

		return uint32(
			typed,
		)

	case uint16:

		return uint32(
			typed,
		)

	case int16:

		return uint32(
			typed,
		)

	case uint32:

		return typed

	case int32:

		return uint32(
			typed,
		)

	case uint64:

		return uint32(
			typed,
		)

	case int64:

		return uint32(
			typed,
		)

	case int:

		return uint32(
			typed,
		)

	case uint:

		return uint32(
			typed,
		)

	default:

		return 0
	}
}

func variantToInt(
	value *ole.VARIANT,
) int {

	if value == nil {
		return 0
	}

	switch typed :=
		value.Value().(type) {

	case int:

		return typed

	case int8:

		return int(typed)

	case uint8:

		return int(typed)

	case int16:

		return int(typed)

	case uint16:

		return int(typed)

	case int32:

		return int(typed)

	case uint32:

		return int(typed)

	case int64:

		return int(typed)

	case uint64:

		return int(typed)

	default:

		return int(
			value.Val,
		)
	}
}
