package detection

import "xe-antishell/internal/model"

// The caller selects this service's scoped directories using the service
// identity attributed to the writer at observation time.
func evaluateProtectedFileWrite(event model.Event, protectedDirs, allowedDirs []string) []model.Finding {
	f := event.File
	if len(protectedDirs) == 0 || event.Type != "file.write" || event.Source != "tetragon" || f == nil ||
		f.PolicyName != "xeas-file-write-v1" || f.Function != "vfs_write" || f.Operation != "write" ||
		!model.ConfirmedFileWrite(f.Path, f.Outcome, f.ReturnValue) {
		return nil
	}
	for _, dir := range allowedDirs {
		if model.WithinObservationDirectory(f.Path, dir) {
			return nil
		}
	}
	for _, dir := range protectedDirs {
		if model.WithinObservationDirectory(f.Path, dir) {
			if !evidenceFieldAvailable(event, "file") {
				return nil
			}
			return operationFinding(event, ruleServiceProtectedFileWrite,
				"서비스가 보호 경로의 파일에 데이터를 썼습니다. 승인된 변경인지 확인하세요.", "protected_file_write", 70)
		}
	}
	return nil
}
