package central

import (
	"reflect"
	"time"
)

// copySnapshotValue preserves nil/empty distinctions and typed model fields.
// It only handles Store data values, never errors or storage implementation
// objects. Contract tests check that all reachable fields support this copy.
func copySnapshotValue[T any](value T) T {
	return copySnapshotReflect(reflect.ValueOf(value)).Interface().(T)
}

var snapshotTimeType = reflect.TypeFor[time.Time]()

func copySnapshotReflect(value reflect.Value) reflect.Value {
	// time.Time is an immutable value; retain its location and monotonic state.
	if value.Type() == snapshotTimeType {
		return value
	}
	switch value.Kind() {
	case reflect.Pointer:
		if value.IsNil() {
			return reflect.Zero(value.Type())
		}
		result := reflect.New(value.Type().Elem())
		result.Elem().Set(copySnapshotReflect(value.Elem()))
		return result
	case reflect.Slice:
		if value.IsNil() {
			return reflect.Zero(value.Type())
		}
		result := reflect.MakeSlice(value.Type(), value.Len(), value.Len())
		for index := 0; index < value.Len(); index++ {
			result.Index(index).Set(copySnapshotReflect(value.Index(index)))
		}
		return result
	case reflect.Array:
		result := reflect.New(value.Type()).Elem()
		for index := 0; index < value.Len(); index++ {
			result.Index(index).Set(copySnapshotReflect(value.Index(index)))
		}
		return result
	case reflect.Map:
		if value.IsNil() {
			return reflect.Zero(value.Type())
		}
		result := reflect.MakeMapWithSize(value.Type(), value.Len())
		iterator := value.MapRange()
		for iterator.Next() {
			result.SetMapIndex(copySnapshotReflect(iterator.Key()), copySnapshotReflect(iterator.Value()))
		}
		return result
	case reflect.Struct:
		result := reflect.New(value.Type()).Elem()
		for index := 0; index < value.NumField(); index++ {
			result.Field(index).Set(copySnapshotReflect(value.Field(index)))
		}
		return result
	default:
		return value
	}
}
