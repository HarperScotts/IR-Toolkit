package local

import (
	"ir-toolkit/internal/model"
	"path/filepath"
)

func (s *CaseStore) ensureTimeline() error {

	s.timelineOnce.Do(
		func() {

			s.timelineByID =
				make(
					map[string]int,
				)

			s.timelineByPID =
				make(
					map[uint32][]int,
				)

			path :=
				filepath.Join(
					s.caseDir,
					"timeline",
					"timeline.json",
				)

			if err :=
				readJSONFile(
					path,
					&s.timeline,
				); err != nil {

				s.timelineErr =
					err

				return
			}

			for index, event := range s.timeline.Events {

				if event.ID != "" {

					s.timelineByID[event.ID] =
						index
				}

				if event.PID != 0 {

					s.timelineByPID[event.PID] =
						append(
							s.timelineByPID[event.PID],
							index,
						)
				}
			}
		},
	)

	return s.timelineErr
}

func (s *CaseStore) Timeline() (
	*model.Timeline,
	error,
) {

	if err :=
		s.ensureTimeline(); err != nil {

		return nil,
			err
	}

	return &s.timeline,
		nil
}

func (s *CaseStore) TimelineEvents() (
	[]model.TimelineEvent,
	error,
) {

	if err :=
		s.ensureTimeline(); err != nil {

		return nil,
			err
	}

	return s.timeline.Events,
		nil
}

func (s *CaseStore) TimelineEventByID(
	id string,
) (
	model.TimelineEvent,
	bool,
	error,
) {

	if err :=
		s.ensureTimeline(); err != nil {

		return model.TimelineEvent{},
			false,
			err
	}

	index,
		ok :=
		s.timelineByID[id]

	if !ok {

		return model.TimelineEvent{},
			false,
			nil
	}

	return s.timeline.Events[index],
		true,
		nil
}

func (s *CaseStore) TimelineEventsByPID(
	pid uint32,
) (
	[]model.TimelineEvent,
	error,
) {

	if err :=
		s.ensureTimeline(); err != nil {

		return nil,
			err
	}

	indexes :=
		s.timelineByPID[pid]

	if len(indexes) == 0 {

		return []model.TimelineEvent{},
			nil
	}

	events :=
		make(
			[]model.TimelineEvent,
			0,
			len(indexes),
		)

	for _, index := range indexes {

		events =
			append(
				events,
				s.timeline.Events[index],
			)
	}

	return events,
		nil
}

func (s *CaseStore) TimelineEventCountByPID(
	pid uint32,
) (
	uint32,
	error,
) {

	if err :=
		s.ensureTimeline(); err != nil {

		return 0,
			err
	}

	return uint32(
			len(
				s.timelineByPID[pid],
			),
		),
		nil
}
