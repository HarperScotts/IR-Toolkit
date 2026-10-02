package local

import (
	"ir-toolkit/internal/store"
	"path/filepath"
)

func (s *CaseStore) ensureCorrelation() error {

	s.correlationOnce.Do(
		func() {

			s.correlationNodeByID =
				make(
					map[string]int,
				)

			s.correlationEdgeByID =
				make(
					map[string]int,
				)

			s.correlationChainByID =
				make(
					map[string]int,
				)

			path :=
				filepath.Join(
					s.caseDir,
					"analysis",
					"historical_correlation.json",
				)

			if err :=
				readJSONFile(
					path,
					&s.correlationAnalysis,
				); err != nil {

				s.correlationErr =
					err

				return
			}

			for index, node := range s.correlationAnalysis.Nodes {

				if node.ID == "" {
					continue
				}

				s.correlationNodeByID[node.ID] =
					index
			}

			for index, edge := range s.correlationAnalysis.Edges {

				if edge.ID == "" {
					continue
				}

				s.correlationEdgeByID[edge.ID] =
					index
			}

			for index, chain := range s.correlationAnalysis.Chains {

				if chain.ID == "" {
					continue
				}

				s.correlationChainByID[chain.ID] =
					index
			}
		},
	)

	return s.correlationErr
}

func (s *CaseStore) HistoricalCorrelation() (
	*store.HistoricalCorrelationRecord,
	error,
) {

	if err :=
		s.ensureCorrelation(); err != nil {

		return nil,
			err
	}

	return &s.correlationAnalysis,
		nil
}

func (s *CaseStore) CorrelationNodes() (
	[]store.CorrelationNodeRecord,
	error,
) {

	if err :=
		s.ensureCorrelation(); err != nil {

		return nil,
			err
	}

	return s.correlationAnalysis.Nodes,
		nil
}

func (s *CaseStore) CorrelationEdges() (
	[]store.CorrelationEdgeRecord,
	error,
) {

	if err :=
		s.ensureCorrelation(); err != nil {

		return nil,
			err
	}

	return s.correlationAnalysis.Edges,
		nil
}

func (s *CaseStore) CorrelationChains() (
	[]store.HistoricalChainRecord,
	error,
) {

	if err :=
		s.ensureCorrelation(); err != nil {

		return nil,
			err
	}

	return s.correlationAnalysis.Chains,
		nil
}

func (s *CaseStore) CorrelationNodeByID(
	id string,
) (
	store.CorrelationNodeRecord,
	bool,
	error,
) {

	if err :=
		s.ensureCorrelation(); err != nil {

		return store.CorrelationNodeRecord{},
			false,
			err
	}

	index,
		ok :=
		s.correlationNodeByID[id]

	if !ok {

		return store.CorrelationNodeRecord{},
			false,
			nil
	}

	return s.correlationAnalysis.Nodes[index],
		true,
		nil
}

func (s *CaseStore) CorrelationEdgeByID(
	id string,
) (
	store.CorrelationEdgeRecord,
	bool,
	error,
) {

	if err :=
		s.ensureCorrelation(); err != nil {

		return store.CorrelationEdgeRecord{},
			false,
			err
	}

	index,
		ok :=
		s.correlationEdgeByID[id]

	if !ok {

		return store.CorrelationEdgeRecord{},
			false,
			nil
	}

	return s.correlationAnalysis.Edges[index],
		true,
		nil
}

func (s *CaseStore) CorrelationChainByID(
	id string,
) (
	store.HistoricalChainRecord,
	bool,
	error,
) {

	if err :=
		s.ensureCorrelation(); err != nil {

		return store.HistoricalChainRecord{},
			false,
			err
	}

	index,
		ok :=
		s.correlationChainByID[id]

	if !ok {

		return store.HistoricalChainRecord{},
			false,
			nil
	}

	return s.correlationAnalysis.Chains[index],
		true,
		nil
}
