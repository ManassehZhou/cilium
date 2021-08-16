// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of Cilium

package speaker

import (
	"errors"
	"fmt"
	"sync"

	"github.com/cilium/cilium/pkg/cidr"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/sirupsen/logrus"

	metallbbgp "go.universe.tf/metallb/pkg/bgp"
	metallbspr "go.universe.tf/metallb/pkg/speaker"
	"golang.org/x/sync/errgroup"
)

var (
	emptyAdverts = []*metallbbgp.Advertisement{}
)

func (s *MetalLBSpeaker) withdraw() {
	var (
		l = log.WithFields(logrus.Fields{
			"component": "MetalLBSpeaker.withdraw",
		})
	)
	var wg sync.WaitGroup // waitgroup here since we don't care about errors
	for _, session := range s.speaker.PeerSessions() {
		wg.Add(1)
		go func(sess metallbspr.Session) { // Need an outer closure to capture session.
			defer wg.Done()
			// providing an empty array of advertisements will
			// provoke the BGP controller to withdrawal any currently
			// advertised bgp routes.
			err := sess.Set(emptyAdverts...)
			if err != nil {
				l.Error("Failed to gracefully remove BGP routes.")
			}
		}(session)
	}
	wg.Wait()
	return
}

func (s *MetalLBSpeaker) announcePodCIDRs(cidrs []string) error {
	sessions := s.speaker.PeerSessions()
	if len(sessions) == 0 {
		return fmt.Errorf("No established BGP session")
	}

	var eg errgroup.Group
	for _, session := range s.speaker.PeerSessions() {
		func(sess metallbspr.Session) { // Need an outer closure to capture session.
			eg.Go(func() error {
				return s.announce(sess, cidrs)
			})
		}(session)
	}

	return eg.Wait()
}

func (s *MetalLBSpeaker) announce(session metallbspr.Session, cidrs []string) error {
	adverts := make([]*metallbbgp.Advertisement, 0, len(cidrs))
	for _, c := range cidrs {
		parsed, err := cidr.ParseCIDR(c)
		if err != nil {
			log.WithError(err).WithField(logfields.CIDR, c).
				Error("Could not announce malformed CIDR. Continuing to next")
			continue
		}
		adverts = append(adverts, &metallbbgp.Advertisement{
			Prefix: parsed.IPNet,
		})
	}
	if len(adverts) == 0 {
		return errors.New("no BGP advertisements made")
	}
	return session.Set(adverts...)
}
