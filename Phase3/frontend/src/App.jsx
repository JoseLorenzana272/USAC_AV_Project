"use client"

import { useState, useEffect } from "react"
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Title,
  Tooltip,
  Legend,
  ArcElement,
  Filler,
} from "chart.js"
import { Line, Doughnut } from "react-chartjs-2"
import {
  Shield,
  Activity,
  Database,
  HardDrive,
  Cpu,
  MemoryStick,
  AlertTriangle,
  CheckCircle,
  Lock,
  Search,
  LogOut,
  Server,
  FileX,
} from "lucide-react"

// Register Chart.js components
ChartJS.register(CategoryScale, LinearScale, PointElement, LineElement, Title, Tooltip, Legend, ArcElement, Filler)

function App() {
  // State for system metrics
  const [metrics, setMetrics] = useState({
    mem_used: 0,
    mem_free: 0,
    mem_cache: 0,
    swap_used: 0,
    active_pages: 0,
    inactive_pages: 0,
    minor_page_faults: 0,
    major_page_faults: 0,
    procesos_top: [
      { name: "Process A", pid: 1234, mem_percent: 12.34 },
      { name: "Process B", pid: 5678, mem_percent: 23.45 },
      { name: "Process C", pid: 9101, mem_percent: 34.56 },
    ],
  })

  // State for quarantine form
  const [filePath, setFilePath] = useState("")
  const [quarantineMessage, setQuarantineMessage] = useState("")
  const [messageType, setMessageType] = useState("")
  const [isScanning, setIsScanning] = useState(false)

  // State for memory usage history
  const [memoryHistory, setMemoryHistory] = useState([])
  const [timeLabels, setTimeLabels] = useState([])

  // State for system status
  const [systemStatus, setSystemStatus] = useState({
    threats: 0,
    scanned: 1247,
    quarantined: 3,
    uptime: "2d 14h 32m",
  })

  // Generate fake system metrics data
  const generateFakeMetrics = () => {
    return {
      mem_used: Math.floor(Math.random() * 2000000) + 1000000,
      mem_free: Math.floor(Math.random() * 1000000) + 500000,
      mem_cache: Math.floor(Math.random() * 500000) + 200000,
      swap_used: Math.floor(Math.random() * 100000),
      active_pages: Math.floor(Math.random() * 100000) + 50000,
      inactive_pages: Math.floor(Math.random() * 50000) + 20000,
      minor_page_faults: Math.floor(Math.random() * 1000),
      major_page_faults: Math.floor(Math.random() * 100),
      procesos_top: [
        { name: "Process A", pid: 1234, mem_percent: Math.random() * 100 },
        { name: "Process B", pid: 5678, mem_percent: Math.random() * 100 },
        { name: "Process C", pid: 9101, mem_percent: Math.random() * 100 },
      ],
    }
  }

  // Update metrics every 5 seconds
  useEffect(() => {
    const initialMetrics = generateFakeMetrics()
    setMetrics(initialMetrics)

    const initialHistory = Array.from({ length: 20 }, (_, i) => Math.floor(Math.random() * 2000000) + 1000000)
    const initialLabels = Array.from({ length: 20 }, (_, i) =>
      new Date(Date.now() - (19 - i) * 5000).toLocaleTimeString("en-US", {
        hour12: false,
        minute: "2-digit",
        second: "2-digit",
      }),
    )

    setMemoryHistory(initialHistory)
    setTimeLabels(initialLabels)

    const interval = setInterval(() => {
      // TODO: Replace with actual API call to Flask backend
      // fetch('/api/stats')
      //   .then(response => response.json())
      //   .then(data => setMetrics(data))
      //   .catch(error => console.error('Error fetching metrics:', error));

      const newMetrics = generateFakeMetrics()
      setMetrics(newMetrics)

      setMemoryHistory((prev) => {
        const newHistory = [...prev.slice(1), newMetrics.mem_used]
        return newHistory
      })

      setTimeLabels((prev) => {
        const newTime = new Date().toLocaleTimeString("en-US", {
          hour12: false,
          minute: "2-digit",
          second: "2-digit",
        })
        return [...prev.slice(1), newTime]
      })

      // Update system status occasionally
      if (Math.random() > 0.7) {
        setSystemStatus((prev) => ({
          ...prev,
          scanned: prev.scanned + Math.floor(Math.random() * 5) + 1,
          threats: Math.random() > 0.9 ? prev.threats + 1 : prev.threats,
        }))
      }
    }, 5000)

    return () => clearInterval(interval)
  }, [])

  // Handle quarantine file action
  const handleQuarantine = async (e) => {
    e.preventDefault()

    if (!filePath.trim()) {
      setQuarantineMessage("Please enter a valid file path")
      setMessageType("error")
      return
    }

    setIsScanning(true)
    setQuarantineMessage("Scanning file...")
    setMessageType("scanning")

    // Simulate scanning delay
    setTimeout(() => {
      // TODO: Replace with actual API call to Flask backend
      // const response = await fetch('/api/quarantine', {
      //   method: 'POST',
      //   headers: { 'Content-Type': 'application/json' },
      //   body: JSON.stringify({ path: filePath }),
      // });
      // const result = await response.json();

      const isSuccess = Math.random() > 0.3
      const result = isSuccess
        ? {
            status: "success",
            message: `File successfully quarantined to /var/quarantine/${filePath.split("/").pop()}`,
          }
        : {
            status: "error",
            message: "Invalid path or file not found",
          }

      setQuarantineMessage(result.message)
      setMessageType(result.status)
      setIsScanning(false)

      if (result.status === "success") {
        setFilePath("")
        setSystemStatus((prev) => ({ ...prev, quarantined: prev.quarantined + 1 }))
      }
    }, 2000)
  }

  // Format bytes to readable format
  const formatBytes = (bytes) => {
    if (bytes === 0) return "0 KB"
    const k = 1024
    const sizes = ["KB", "MB", "GB", "TB"]
    const i = Math.floor(Math.log(bytes) / Math.log(k))
    return Number.parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + " " + sizes[i]
  }

  // Create minimal donut chart data
  const createDonutData = (used, total) => {
    return {
      datasets: [
        {
          data: [used, total - used],
          backgroundColor: ["#3b82f6", "#27272a"],
          borderWidth: 0,
          cutout: "80%",
        },
      ],
    }
  }

  // Minimal donut chart options
  const donutOptions = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: { display: false },
      tooltip: { enabled: false },
    },
    elements: {
      arc: { borderWidth: 0 },
    },
  }

  // Clean line chart data
  const lineChartData = {
    labels: timeLabels,
    datasets: [
      {
        label: "Memory Usage",
        data: memoryHistory,
        borderColor: "#3b82f6",
        backgroundColor: "rgba(59, 130, 246, 0.05)",
        borderWidth: 2,
        fill: true,
        tension: 0.1,
        pointRadius: 0,
        pointHoverRadius: 4,
        pointHoverBackgroundColor: "#3b82f6",
        pointHoverBorderColor: "#ffffff",
        pointHoverBorderWidth: 2,
      },
    ],
  }

  // Clean line chart options
  const lineChartOptions = {
    responsive: true,
    maintainAspectRatio: false,
    interaction: {
      intersect: false,
      mode: "index",
    },
    plugins: {
      legend: { display: false },
      tooltip: {
        backgroundColor: "#18181b",
        titleColor: "#f4f4f5",
        bodyColor: "#a1a1aa",
        borderColor: "#3f3f46",
        borderWidth: 1,
        cornerRadius: 6,
        displayColors: false,
        callbacks: {
          title: (context) => `${context[0].label}`,
          label: (context) => `${formatBytes(context.parsed.y)}`,
        },
      },
    },
    scales: {
      x: {
        grid: {
          color: "#27272a",
          drawBorder: false,
        },
        ticks: {
          color: "#71717a",
          font: { size: 11 },
          maxTicksLimit: 8,
        },
      },
      y: {
        grid: {
          color: "#27272a",
          drawBorder: false,
        },
        ticks: {
          color: "#71717a",
          font: { size: 11 },
          callback: (value) => formatBytes(value),
        },
      },
    },
  }

  // System metrics data
  const metricCards = [
    {
      title: "Memory Used",
      value: formatBytes(metrics.mem_used),
      icon: MemoryStick,
      chart: createDonutData(metrics.mem_used, metrics.mem_used + metrics.mem_free),
      percentage: Math.round((metrics.mem_used / (metrics.mem_used + metrics.mem_free)) * 100),
    },
    {
      title: "Memory Free",
      value: formatBytes(metrics.mem_free),
      icon: Database,
      chart: createDonutData(metrics.mem_free, metrics.mem_used + metrics.mem_free),
      percentage: Math.round((metrics.mem_free / (metrics.mem_used + metrics.mem_free)) * 100),
    },
    {
      title: "Cache Memory",
      value: formatBytes(metrics.mem_cache),
      icon: Cpu,
      chart: createDonutData(metrics.mem_cache, metrics.mem_cache + 500000),
      percentage: Math.round((metrics.mem_cache / (metrics.mem_cache + 500000)) * 100),
    },
    {
      title: "Swap Used",
      value: formatBytes(metrics.swap_used),
      icon: HardDrive,
      chart: createDonutData(metrics.swap_used, Math.max(metrics.swap_used + 100000, 100000)),
      percentage: Math.round((metrics.swap_used / Math.max(metrics.swap_used + 100000, 100000)) * 100),
    },
    {
      title: "Active Pages",
      value: metrics.active_pages.toLocaleString(),
      icon: Activity,
      chart: createDonutData(metrics.active_pages, metrics.active_pages + metrics.inactive_pages),
      percentage: Math.round((metrics.active_pages / (metrics.active_pages + metrics.inactive_pages)) * 100),
    },
    {
      title: "Inactive Pages",
      value: metrics.inactive_pages.toLocaleString(),
      icon: Server,
      chart: createDonutData(metrics.inactive_pages, metrics.active_pages + metrics.inactive_pages),
      percentage: Math.round((metrics.inactive_pages / (metrics.active_pages + metrics.inactive_pages)) * 100),
    },
    {
      title: "Minor Page Faults",
      value: metrics.minor_page_faults.toLocaleString(),
      icon: AlertTriangle,
      chart: createDonutData(metrics.minor_page_faults, 10000),
      percentage: Math.round((metrics.minor_page_faults / 10000) * 100),
    },
    {
      title: "Major Page Faults",
      value: metrics.major_page_faults.toLocaleString(),
      icon: FileX,
      chart: createDonutData(metrics.major_page_faults, 1000),
      percentage: Math.round((metrics.major_page_faults / 1000) * 100),
    },
  ]

  return (
    <div className="min-h-screen bg-zinc-950 text-zinc-100">
      {/* Header */}
      <header className="border-b border-zinc-800 bg-zinc-950/80 backdrop-blur-sm sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-6 lg:px-8">
          <div className="flex justify-between items-center h-16">
            {/* Logo */}
            <div className="flex items-center space-x-3">
              <Shield className="w-6 h-6 text-blue-500" />
              <div>
                <h1 className="text-xl font-semibold text-zinc-100">USAC-AV</h1>
                <p className="text-xs text-zinc-500">Antivirus Dashboard</p>
              </div>
            </div>

            {/* Status */}
            <div className="hidden md:flex items-center space-x-6">
              <div className="flex items-center space-x-2">
                <div className="w-2 h-2 bg-green-500 rounded-full"></div>
                <span className="text-sm text-zinc-400">Online</span>
              </div>
              <div className="flex items-center space-x-2">
                <Activity className="w-4 h-4 text-zinc-400" />
                <span className="text-sm text-zinc-400">Monitoring</span>
              </div>
            </div>

            {/* Logout */}
            <button className="flex items-center space-x-2 px-3 py-2 text-sm text-zinc-400 hover:text-zinc-100 hover:bg-zinc-800 rounded-md">
              <LogOut className="w-4 h-4" />
              <span>Logout</span>
            </button>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="max-w-7xl mx-auto px-6 lg:px-8 py-8">
        {/* Status Overview */}
        <section className="mb-8">
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            <div className="bg-zinc-900 border border-zinc-800 rounded-lg p-4">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-zinc-400">Active Threats</p>
                  <p className="text-2xl font-semibold text-zinc-100">{systemStatus.threats}</p>
                </div>
                <CheckCircle className="w-8 h-8 text-green-500" />
              </div>
            </div>

            <div className="bg-zinc-900 border border-zinc-800 rounded-lg p-4">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-zinc-400">Files Scanned</p>
                  <p className="text-2xl font-semibold text-zinc-100">{systemStatus.scanned.toLocaleString()}</p>
                </div>
                <Search className="w-8 h-8 text-blue-500" />
              </div>
            </div>

            <div className="bg-zinc-900 border border-zinc-800 rounded-lg p-4">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-zinc-400">Quarantined</p>
                  <p className="text-2xl font-semibold text-zinc-100">{systemStatus.quarantined}</p>
                </div>
                <FileX className="w-8 h-8 text-orange-500" />
              </div>
            </div>

            <div className="bg-zinc-900 border border-zinc-800 rounded-lg p-4">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-zinc-400">Uptime</p>
                  <p className="text-lg font-semibold text-zinc-100">{systemStatus.uptime}</p>
                </div>
                <Cpu className="w-8 h-8 text-purple-500" />
              </div>
            </div>
          </div>
        </section>

        {/* System Metrics */}
        <section className="mb-8">
          <div className="mb-6">
            <h2 className="text-2xl font-semibold text-zinc-100 mb-2">System Metrics</h2>
            <p className="text-zinc-400">Real-time system performance monitoring</p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            {metricCards.map((card, index) => {
              const Icon = card.icon

              return (
                <div
                  key={card.title}
                  className="bg-zinc-900 border border-zinc-800 rounded-lg p-6 hover:border-zinc-700"
                >
                  <div className="flex items-start justify-between mb-4">
                    <div className="flex items-center space-x-3">
                      <div className="p-2 bg-zinc-800 rounded-lg">
                        <Icon className="w-5 h-5 text-blue-500" />
                      </div>
                      <div>
                        <h3 className="text-sm font-medium text-zinc-300">{card.title}</h3>
                        <p className="text-xs text-zinc-500">{card.percentage}%</p>
                      </div>
                    </div>
                  </div>

                  <div className="flex items-end justify-between">
                    <div>
                      <p className="text-xl font-semibold text-zinc-100">{card.value}</p>
                    </div>
                    <div className="w-12 h-12">
                      <Doughnut data={card.chart} options={donutOptions} />
                    </div>
                  </div>
                </div>
              )
            })}
          </div>
        </section>

        {/* Top Processes */}
        <section className="mb-8">
          <div className="bg-zinc-900 border border-zinc-800 rounded-lg p-6">
            <div className="mb-6">
              <h2 className="text-xl font-semibold text-zinc-100 mb-2">Top Processes</h2>
              <p className="text-zinc-400">Processes consuming the most memory</p>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-left text-sm text-zinc-300">
                <thead>
                  <tr className="border-b border-zinc-800">
                    <th className="py-3 px-4">Name</th>
                    <th className="py-3 px-4">PID</th>
                    <th className="py-3 px-4">Memory Usage (%)</th>
                  </tr>
                </thead>
                <tbody>
                  {metrics.procesos_top.map((proc, index) => (
                    <tr key={index} className="border-b border-zinc-800/50 hover:bg-zinc-800">
                      <td className="py-3 px-4">{proc.name}</td>
                      <td className="py-3 px-4">{proc.pid}</td>
                      <td className="py-3 px-4">{proc.mem_percent.toFixed(2)}%</td>
                    </tr>
                  ))}
                  {metrics.procesos_top.length === 0 && (
                    <tr>
                      <td colSpan="3" className="py-3 px-4 text-center text-zinc-500">
                        No process data available
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </section>

        {/* Quarantine Section */}
        <section className="mb-8">
          <div className="bg-zinc-900 border border-zinc-800 rounded-lg p-6">
            <div className="flex items-center space-x-3 mb-6">
              <Lock className="w-6 h-6 text-red-500" />
              <div>
                <h2 className="text-xl font-semibold text-zinc-100">File Quarantine</h2>
                <p className="text-zinc-400">Isolate suspicious files from the system</p>
              </div>
            </div>

            <form onSubmit={handleQuarantine} className="max-w-2xl">
              <div className="mb-4">
                <label htmlFor="filePath" className="block text-sm font-medium text-zinc-300 mb-2">
                  File Path
                </label>
                <input
                  type="text"
                  id="filePath"
                  value={filePath}
                  onChange={(e) => setFilePath(e.target.value)}
                  placeholder="/tmp/suspicious_file.exe"
                  className="w-full px-4 py-3 bg-zinc-800 border border-zinc-700 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent text-zinc-100 placeholder-zinc-500"
                  disabled={isScanning}
                />
              </div>

              <button
                type="submit"
                disabled={isScanning}
                className="px-6 py-3 bg-red-600 hover:bg-red-700 text-white font-medium rounded-lg disabled:opacity-50 disabled:cursor-not-allowed flex items-center space-x-2"
              >
                {isScanning ? (
                  <>
                    <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin"></div>
                    <span>Scanning...</span>
                  </>
                ) : (
                  <>
                    <Lock className="w-4 h-4" />
                    <span>Quarantine File</span>
                  </>
                )}
              </button>
            </form>

            {/* Status Message */}
            {quarantineMessage && (
              <div
                className={`mt-4 p-4 rounded-lg border ${
                  messageType === "success"
                    ? "bg-green-900/20 border-green-800 text-green-200"
                    : messageType === "error"
                      ? "bg-red-900/20 border-red-800 text-red-200"
                      : "bg-blue-900/20 border-blue-800 text-blue-200"
                }`}
              >
                <div className="flex items-center space-x-2">
                  {messageType === "success" && <CheckCircle className="w-4 h-4 text-green-400" />}
                  {messageType === "error" && <AlertTriangle className="w-4 h-4 text-red-400" />}
                  {messageType === "scanning" && (
                    <div className="w-4 h-4 border-2 border-blue-400/30 border-t-blue-400 rounded-full animate-spin"></div>
                  )}
                  <span className="text-sm">{quarantineMessage}</span>
                </div>
              </div>
            )}
          </div>
        </section>

        {/* Memory Usage Chart */}
        <section>
          <div className="bg-zinc-900 border border-zinc-800 rounded-lg p-6">
            <div className="mb-6">
              <h2 className="text-xl font-semibold text-zinc-100 mb-2">Memory Usage</h2>
              <p className="text-zinc-400">Real-time memory consumption over time</p>
            </div>
            <div className="h-64">
              <Line data={lineChartData} options={lineChartOptions} />
            </div>
          </div>
        </section>
      </main>
    </div>
  )
}

export default App
