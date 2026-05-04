# Community Feedback Drafts

## GitHub Discussions Setup

Recommended categories:

- Announcements
- Feedback
- Ideas
- Polls
- Help

Recommended pinned welcome discussion title:

`Welcome to the AuditOS beta`

Recommended pinned welcome discussion body:

```md
Thanks for trying AuditOS.

AuditOS helps you see what is starting, running, and changing on your computer in one place. It focuses on startup items, browser extensions and related background browser activity, scheduled tasks, certificates, DNS/proxy settings, and network-related system activity.

AuditOS presents that information in clearer, more organized terms so people can better understand what deserves attention and make more informed decisions about what may no longer be necessary.

All audit data stays on your machine, and the app does not automatically remove, disable, or change system components.

This project is still in beta, and I’m looking for blunt, practical feedback.

What would help most right now:

- crashes or hangs during Quick Audit or Deep Audit
- findings that look incorrect or too noisy
- sections that feel confusing or hard to interpret
- places where the app made you more or less likely to trust its output
- use cases where this would actually be useful in real life

If you’re posting feedback, please include:

- your OS and version
- whether you ran Quick Audit or Deep Audit
- what you expected to happen
- what actually happened
- screenshots or exported report JSON if helpful

If you just want to answer one question, answer this:

Would this be useful enough for you to keep installed, and if not, what is missing?
```

Recommended first poll title:

`What would make AuditOS useful enough to keep installed?`

Recommended poll options:

- Faster, trustworthy Quick Audit
- Clearer explanations of findings
- Better signal and less noise
- Better change tracking over time
- A clearer "where do I look next?" story
- More network visibility

## GitHub Discussion Post

Suggested title:

`Feedback wanted: would you use a tool to inspect unexpected startup, browser, and network activity?`

Suggested body:

```md
I’m looking for honest feedback on AuditOS, a desktop audit app for macOS and Windows.

AuditOS is built around a simple goal: help people see what is starting, running, and changing on their computer in one place.

It focuses on startup items, browser extensions and related background browser activity, scheduled tasks, and network-related system activity. It tries to present that information in clearer terms so people can better understand what deserves attention and what may no longer be necessary.

Audit data stays on your machine, and the app does not automatically remove, disable, or change anything.

Right now the app can audit:

- browser extensions
- proxy settings
- DNS settings
- network interfaces
- startup items
- scheduled tasks
- certificates

Deep Audit also adds:

- active network connections
- listening ports
- routes / default routes

I’m trying to answer a pretty basic question before I spend much more time on this:

Is this a real recurring problem for other people, or is it only interesting to me?

I’d especially love feedback on:

- who this is actually for
- whether the current feature set gives you a useful place to start looking
- what would make you trust the results
- whether keeping all audit data local matters once the core problem is compelling
- whether you would ever run this more than once

If you try it, I’d love to know what felt useful, what felt noisy, and what felt confusing.
```

## Show HN Draft

Suggested title:

`Show HN: AuditOS, a desktop tool for inspecting unexpected startup, browser, and network activity`

Suggested post body:

```text
Hi HN,

I built AuditOS because I wanted one place to see what is starting, running, and changing on my computer.

It focuses on startup items, browser extensions and related background browser activity, scheduled tasks, and network-related system activity, then tries to present that information in clearer terms so it is easier to tell what deserves attention and what may no longer be necessary.

AuditOS is a desktop app for macOS and Windows that tries to pull that into one place. It currently audits things like:

- browser extensions
- proxy settings
- DNS settings
- startup items
- scheduled tasks
- certificates
- network interfaces

There are two modes:

- Quick Audit: a faster pass for common checks
- Deep Audit: includes live network visibility like active connections, listening ports, and routes

The app can also save a baseline and compare later scans so you can see what changed.

A couple things I care about:

- all audits run locally
- the app does not automatically change or remove anything
- there is no signup or account requirement

This is still beta software, and I’m mainly trying to answer whether this is genuinely useful to anyone besides me.

The feedback I’d value most:

1. Is this a real enough problem that you would want a tool for it?
2. Does keeping all audit data local matter once the core problem is clear?
3. What would make you trust or distrust a tool like this?
4. What use case would make you install it and run it again?

If you try it and it crashes, produces noisy findings, or feels confusing, that’s especially helpful to hear.
```
