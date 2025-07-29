# Scout Vite Template

This is a [Vite](https://vite.dev) project bootstrapped with React + TypeScript and configured with TailwindCSS v4 and ShadCN UI.

## Getting Started

First, run the development server:

```bash
bun dev
```

Open [http://localhost:5173](http://localhost:5173) with your browser to see the result.

You can start editing the page by modifying `src/App.tsx`. The page auto-updates as you edit the file.

## Project Configuration

### Package Management

This project uses [Bun](https://bun.sh/) as the package manager:

- Install dependencies: `bun add <package-name>`
- Run scripts: `bun <script-name>`
- Manage dev dependencies: `bun add -d <package-name>`

### Theme Customization

The project uses Tailwind CSS V4 with a theme defined in:

- `src/index.css` - For CSS variables including colors in OKLCH format and custom theming
- Tailwind V4 uses the new `@theme` directive for configuration

### ShadCN UI Components

This project uses [ShadCN UI](https://ui.shadcn.com) for styled components. The components are incorporated directly into the codebase (not as dependencies), making them fully customizable. All components have been installed:

- accordion
- alert-dialog
- alert
- aspect-ratio
- avatar
- badge
- breadcrumb
- button
- calendar
- card
- carousel
- chart
- checkbox
- collapsible
- command
- context-menu
- dialog
- drawer
- dropdown-menu
- form
- hover-card
- input-otp
- input
- label
- menubar
- navigation-menu
- pagination
- popover
- progress
- radio-group
- scroll-area
- select
- separator
- sheet
- skeleton
- slider
- sonner
- switch
- table
- tabs
- textarea
- toast
- toggle-group
- toggle

### Icon Library

[Lucide React](https://lucide.dev/) is the preferred icon library for this project, as specified in components.json. Always use Lucide icons to maintain consistency:

```tsx
import { ArrowRight } from "lucide-react";

// Use in components
<Button>
  <span>Click me</span>
  <ArrowRight />
</Button>;
```

### Font Configuration

This project uses Google Fonts with:

- Inter (sans-serif)
- Playfair Display (serif)

The font is imported via Google Fonts CDN in `src/index.css` and configured in the Tailwind theme:

```css
@import url("https://fonts.googleapis.com/css2?family=Inter:ital,opsz,wght@0,14..32,100..900;1,14..32,100..900&display=swap");
@import url("https://fonts.googleapis.com/css2?family=Playfair+Display:ital,wght@0,400..900;1,400..900&display=swap");

@theme inline {
  --font-sans: "Inter", ui-sans-serif, system-ui, sans-serif;
  --font-serif: "Playfair Display", ui-serif, Georgia, serif;
}
```

To change or update fonts:

1. Update the Google Fonts import in `src/index.css`
2. Modify the `--font-sans` variable in the `@theme` directive

## Build and Deploy

Build the project:

```bash
bun run build
```

Preview the production build:

```bash
bun run preview
```

The built files will be in the `dist` directory, ready for deployment to any static hosting service.
