import { PageLayout, SharedLayout } from "./quartz/cfg"
import * as Component from "./quartz/components"

// components shared across all pages
export const sharedPageComponents: SharedLayout = {
  head: Component.Head(),
  header: [
    Component.Flex({
      components: [
        { Component: Component.PageTitle() },
        { Component: Component.Spacer() },
        { Component: Component.Search() },
        { Component: Component.Darkmode() },
      ],
    }),
  ],
  afterBody: [
    Component.MobileOnly(
      Component.Graph({
        localGraph: {
          drag: true,
          zoom: true,
          depth: 1,
          scale: 1.1,
          repelForce: 0.5,
          centerForce: 0.3,
          linkDistance: 30,
          fontSize: 0.6,
          opacityScale: 1,
          showTags: true,
          removeTags: [],
        },
      })
    ),
  ],
  footer: Component.Footer({
    links: {
      "Wargames": "https://www.pwnthe.website",
      "Discord Community": "https://discord.gg/v9EEVKPWm2",
    },
  }),
}

// components for pages that display a single page (e.g. a single note)
export const defaultContentPageLayout: PageLayout = {
  beforeBody: [
    Component.ConditionalRender({
      component: Component.Breadcrumbs(),
      condition: (page) => page.fileData.slug !== "index" && !page.fileData.slug?.startsWith("tags/"),
    }),
    Component.ArticleTitle(),
    Component.ContentMeta(),
    Component.TagList(),
  ],
  left: [
    Component.MobileOnly(Component.Spacer()),
    Component.DesktopOnly(
      Component.Graph({
        localGraph: {
          drag: true,
          zoom: true,
          depth: 1,
          scale: 1.1,
          repelForce: 0.5,
          centerForce: 0.3,
          linkDistance: 30,
          fontSize: 0.6,
          opacityScale: 1,
          showTags: true,
          removeTags: [],
        },
        globalGraph: {
          drag: true,
          zoom: true,
          depth: -1,
          scale: 0.9,
          repelForce: 0.5,
          centerForce: 0.3,
          linkDistance: 30,
          fontSize: 0.6,
          opacityScale: 1,
          showTags: true,
          removeTags: [],
        },
      })
    ),
    Component.DesktopOnly(Component.TableOfContents()),
  ],
  right: [
    Component.DesktopOnly(
      Component.Explorer({
        title: "Notes",
        folderClickBehavior: "link",
        folderDefaultState: "collapsed",
        useSavedState: true,
        sortFn: (a, b) => {
          if ((!a.isFolder && !b.isFolder) || (a.isFolder && b.isFolder)) {
            return a.displayName.localeCompare(b.displayName, undefined, {
              numeric: true,
              sensitivity: "base",
            })
          }
          if (!a.isFolder && b.isFolder) return 1
          return -1
        },
        filterFn: (node) => node.slugSegment !== "tags",
      })
    ),
    Component.DesktopOnly(
      Component.RecentNotes({
        title: "Recently Updated",
        limit: 4,
        showTags: false,
        filter: (f) => f.slug !== "index" && !f.slug?.startsWith("tags/"),
        linkToMore: false,
      })
    ),
    Component.DesktopOnly(Component.Backlinks()),
  ],
}

// components for pages that display lists of pages  (e.g. tags or folders)
export const defaultListPageLayout: PageLayout = {
  beforeBody: [
    Component.Breadcrumbs(),
    Component.ArticleTitle(),
    Component.ContentMeta(),
  ],
  left: [
    Component.MobileOnly(Component.Spacer()),
    Component.DesktopOnly(
      Component.Graph({
        localGraph: {
          drag: true,
          zoom: true,
          depth: 1,
          scale: 1.1,
          repelForce: 0.5,
          centerForce: 0.3,
          linkDistance: 30,
          fontSize: 0.6,
          opacityScale: 1,
          showTags: true,
        },
      })
    ),
  ],
  right: [
    Component.DesktopOnly(
      Component.Explorer({
        title: "Notes",
        folderClickBehavior: "link",
        folderDefaultState: "collapsed",
        useSavedState: true,
      })
    ),
    Component.DesktopOnly(
      Component.RecentNotes({
        title: "Recently Updated",
        limit: 5,
        showTags: false,
      })
    ),
  ],
}
