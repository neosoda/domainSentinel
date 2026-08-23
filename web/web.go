package web

import "embed"

// FS embeds all HTML templates and static assets for DomainSentinel.
//
//go:embed templates/* static/*
var FS embed.FS
