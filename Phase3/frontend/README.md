# USAC-AV Dashboard

A clean, minimalist React dashboard for the USAC-AV antivirus system. Built with React, Vite, and Tailwind CSS for a professional dark mode experience.

## Features

- **Clean Design**: Minimalist dark theme with subtle borders and spacing
- **Real-time Metrics**: Live system performance monitoring
- **File Quarantine**: Simple interface for isolating suspicious files
- **Responsive Layout**: Works seamlessly on desktop and mobile
- **Professional UI**: Clean typography and consistent spacing

## Tech Stack

- **React 18** - Frontend framework
- **Vite** - Build tool and dev server
- **Tailwind CSS** - Utility-first CSS framework
- **Chart.js** - Data visualization
- **Lucide React** - Icon system
- **Inter Font** - Clean, readable typography

## Getting Started

### Prerequisites

- Node.js 16+
- npm or yarn

### Installation

1. **Install dependencies**
   \`\`\`bash
   npm install
   \`\`\`

2. **Start development server**
   \`\`\`bash
   npm run dev
   \`\`\`

3. **Open browser**
   Navigate to `http://localhost:5173`

### Build for Production

\`\`\`bash
npm run build
npm run preview
\`\`\`

## Deployment

### Vercel

\`\`\`bash
npm install -g vercel
vercel --prod
\`\`\`

### Other Platforms

Build the project and upload the `dist` folder to your hosting provider.

## Flask Backend Integration

### API Endpoints

#### System Metrics - `GET /api/stats`
\`\`\`json
{
  "mem_used": 1234567,
  "mem_free": 2345678,
  "mem_cache": 345678,
  "swap_used": 12345,
  "active_pages": 567890,
  "inactive_pages": 123456
}
\`\`\`

#### File Quarantine - `POST /api/quarantine`
\`\`\`json
// Request
{ "path": "/tmp/suspicious_file.exe" }

// Response
{ "status": "success", "message": "File quarantined successfully" }
\`\`\`

### Integration Steps

Replace the fake data sections in `src/App.jsx`:

\`\`\`javascript
// Replace metrics fetching (around line 60)
useEffect(() => {
  const fetchMetrics = async () => {
    try {
      const response = await fetch('/api/stats');
      const data = await response.json();
      setMetrics(data);
    } catch (error) {
      console.error('Error fetching metrics:', error);
    }
  };

  fetchMetrics();
  const interval = setInterval(fetchMetrics, 5000);
  return () => clearInterval(interval);
}, []);

// Replace quarantine handler (around line 120)
const handleQuarantine = async (e) => {
  e.preventDefault();
  
  try {
    const response = await fetch('/api/quarantine', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ path: filePath }),
    });
    
    const result = await response.json();
    setQuarantineMessage(result.message);
    setMessageType(result.status);
  } catch (error) {
    setQuarantineMessage('Network error');
    setMessageType('error');
  }
};
\`\`\`

## Project Structure

\`\`\`
src/
├── App.jsx          # Main dashboard component
├── main.jsx         # React entry point
└── index.css        # Global styles

Configuration:
├── package.json     # Dependencies
├── vite.config.js   # Vite configuration
├── tailwind.config.js # Tailwind configuration
├── index.html       # HTML entry point
└── README.md        # Documentation
\`\`\`

## Customization

### Colors

The dashboard uses a zinc color palette. To customize:

\`\`\`css
/* In src/index.css */
:root {
  --background: #09090b;    /* zinc-950 */
  --card: #18181b;          /* zinc-900 */
  --border: #27272a;        /* zinc-800 */
  --accent: #3b82f6;        /* blue-500 */
}
\`\`\`

### Layout

Modify the grid layouts in `App.jsx`:

\`\`\`javascript
// Status cards: 1 column on mobile, 4 on desktop
className="grid grid-cols-1 md:grid-cols-4 gap-4"

// Metrics cards: 1 column on mobile, 2 on tablet, 3 on desktop
className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6"
\`\`\`

## Browser Support

- Chrome 90+
- Firefox 88+
- Safari 14+
- Edge 90+

## License

MIT License
