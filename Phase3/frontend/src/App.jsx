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
  RotateCcw,
} from "lucide-react"
import io from "socket.io-client"

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
    procesos_top: [],
    quarantine_list: [],
  })

  // State for quarantine form
  const [filePath, setFilePath] = useState("")
  const [quarantineMessage, setQuarantineMessage] = useState("")
  const [messageType, setMessageType] = useState("")
  const [isScanning, setIsScanning] = useState(false)
  const [restoringFiles, setRestoringFiles] = useState(new Set())

  // State for memory usage history
  const [memoryHistory, setMemoryHistory] = useState(Array(60).fill(0));
  const [timeLabels, setTimeLabels] = useState(Array(60).fill(""));

  // State for system status
  const [systemStatus, setSystemStatus] = useState({
    threats: 0,
    scanned: 0,
    quarantined: 0,
    uptime: "0h 0m 0s",
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
      quarantine_list: [
        { filename: "test1.txt", original_path: "/tmp/test1.txt" },
        { filename: "malicious.exe", original_path: "/bin/malicious.exe" },
      ],
    }
  }

  // Initialize WebSocket
  useEffect(() => {
    const socket = io("http://172.16.198.130:5000", { transports: ["websocket"] })

    socket.on("connect", () => {
      console.log("Connected to WebSocket")
    })

    socket.on("stats_update", ({ stats, alerts }) => {
      setMetrics((prev) => ({
        ...prev,
        mem_used: stats.memoria_usada * 1000 || 0,
        mem_free: stats.memoria_libre * 1000 || 0,
        mem_cache: stats.memoria_cache * 1000 || 0,
        swap_used: stats.swap_usada * 1000 || 0,
        active_pages: stats.paginas_activas || 0,
        inactive_pages: stats.paginas_inactivas || 0,
        minor_page_faults: stats.fallos_menores || 0,
        major_page_faults: stats.fallos_mayores || 0,
        procesos_top: stats.procesos_top.map((proc) => ({
          name: proc.nombre,
          pid: proc.pid,
          mem_percent: proc.memoria_pct,
        })) || [],
        // Preserve quarantine_list
        quarantine_list: prev.quarantine_list,
      }))
      setMemoryHistory((prev) => [...prev.slice(-59), stats.memoria_usada * 1000 || 0])
      setTimeLabels((prev) => [
        ...prev.slice(1),
        new Date(stats.timestamp * 1000).toLocaleTimeString("en-US", {
          hour12: false,
          minute: "2-digit",
          second: "2-digit",
        }),
      ])
      setSystemStatus((prev) => ({
        ...prev,
        scanned: prev.scanned + 1,
        threats: stats.fallos_mayores > 100 ? prev.threats + 1 : prev.threats,
        uptime: formatUptime(),
      }))
      if (alerts && alerts.length > 0) {
        setQuarantineMessage(alerts[0].message)
        setMessageType(alerts[0].severity === "critical" ? "error" : "warning")
      }
    })

    socket.on("disconnect", () => {
      console.log("Disconnected from WebSocket")
      setQuarantineMessage("Lost connection to backend")
      setMessageType("error")
    })

    // Fetch initial quarantine list
    fetchQuarantineList()

    return () => {
      socket.disconnect()
    }
  }, [])

  // Fetch quarantine list
  const fetchQuarantineList = async () => {
    try {
      const response = await fetch("http://172.16.198.130:5000/api/quarantine")
      const data = await response.json()
      if (data.status === "success") {
        setMetrics((prev) => ({
          ...prev,
          quarantine_list: data.quarantine_list,
        }))
        setSystemStatus((prev) => ({
          ...prev,
          quarantined: data.quarantine_list.length,
        }))
      } else {
        setQuarantineMessage(data.message)
        setMessageType("error")
      }
    } catch (error) {
      setQuarantineMessage(`Failed to fetch quarantine list: ${error.message}`)
      setMessageType("error")
    }
  }

  const [startTime, setStartTime] = useState(Math.floor(Date.now() / 1000));

  const formatUptime = () => {
    const now = Math.floor(Date.now() / 1000);
    const uptimeSeconds = now - startTime;
    if (uptimeSeconds < 0) return "0d 0h 0m";
    const days = Math.floor(uptimeSeconds / 86400);
    const hours = Math.floor((uptimeSeconds % 86400) / 3600);
    const minutes = Math.floor((uptimeSeconds % 3600) / 60);
    return `${days}d ${hours}h ${minutes}m`;
  };

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

    try {
      const response = await fetch("http://172.16.198.130:5000/api/quarantine", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ path: filePath }),
      })
      const result = await response.json()
      setQuarantineMessage(result.message)
      setMessageType(result.status)
      setIsScanning(false)

      if (result.status === "success" && !result.message.includes("is clean")) {
        const filename = filePath.split("/").pop()
        setFilePath("")
        setMetrics((prev) => {
          const newQuarantineList = [...prev.quarantine_list, { filename, original_path: filePath }]
          setSystemStatus((prevStatus) => ({
            ...prevStatus,
            quarantined: newQuarantineList.length,
          }))
          return {
            ...prev,
            quarantine_list: newQuarantineList,
          }
        })
      }
    } catch (error) {
      setQuarantineMessage(`Quarantine failed: ${error.message}`)
      setMessageType("error")
      setIsScanning(false)
    }
  }

  // Handle restore file action
  const handleRestore = async (filename) => {
    if (!confirm(`Are you sure you want to restore ${filename}?`)) return
    setRestoringFiles((prev) => new Set(prev).add(filename))
    setQuarantineMessage(`Restoring ${filename}...`)
    setMessageType("scanning")

    try {
      const response = await fetch("http://172.16.198.130:5000/api/restore", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ filename }),
      })
      const result = await response.json()
      setQuarantineMessage(result.message)
      setMessageType(result.status)
      setRestoringFiles((prev) => {
        const next = new Set(prev)
        next.delete(filename)
        return next
      })

      if (result.status === "success") {
        setMetrics((prev) => {
          const newQuarantineList = prev.quarantine_list.filter((f) => f.filename !== filename)
          setSystemStatus((prevStatus) => ({
            ...prevStatus,
            quarantined: newQuarantineList.length,
          }))
          return {
            ...prev,
            quarantine_list: newQuarantineList,
          }
        })
      }
    } catch (error) {
      setQuarantineMessage(`Restore failed: ${error.message}`)
      setMessageType("error")
      setRestoringFiles((prev) => {
        const next = new Set(prev)
        next.delete(filename)
        return next
      })
    }
  }

  // Format bytes to readable format
  const formatBytes = (bytes) => {
    if (bytes === 0) return "0 KB"
    const k = 1000
    const sizes = ["B", "KB", "MB", "GB", "TB"];
    const i = Math.floor(Math.log(bytes) / Math.log(k))
    return Number.parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i]
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
      chart: createDonutData(metrics.mem_cache, metrics.mem_cache + metrics.mem_free),
      percentage: Math.round((metrics.mem_cache / (metrics.mem_cache + metrics.mem_free)) * 100),
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
      chart: createDonutData(metrics.minor_page_faults, metrics.minor_page_faults + 100000),
      percentage: Math.min(100, Math.round((metrics.minor_page_faults / 1000000) * 100)) || 0,
    },
    {
      title: "Major Page Faults",
      value: metrics.major_page_faults.toLocaleString(),
      icon: FileX,
      chart: createDonutData(metrics.major_page_faults, metrics.major_page_faults + 1000),
      percentage: Math.min(100, Math.round((metrics.major_page_faults / 10000) * 100)) || 0,
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
            {metricCards.map((card) => {
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

            <form onSubmit={handleQuarantine} className="max-w-2xl mb-6">
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

            {/* Quarantined Files Table */}
            <div className="mt-6">
              <h3 className="text-lg font-semibold text-zinc-100 mb-2">Quarantined Files</h3>
              <p className="text-zinc-400 mb-4">List of files in quarantine</p>
              <div className="overflow-x-auto">
                <table className="w-full text-left text-sm text-zinc-300">
                  <thead>
                    <tr className="border-b border-zinc-800">
                      <th className="py-3 px-4">Filename</th>
                      <th className="py-3 px-4">Original Path</th>
                      <th className="py-3 px-4">Action</th>
                    </tr>
                  </thead>
                  <tbody>
                    {metrics.quarantine_list.map((file, index) => (
                      <tr key={index} className="border-b border-zinc-800/50 hover:bg-zinc-800">
                        <td className="py-3 px-4">{file.filename}</td>
                        <td className="py-3 px-4">{file.original_path}</td>
                        <td className="py-3 px-4">
                          <button
                            onClick={() => handleRestore(file.filename)}
                            disabled={restoringFiles.has(file.filename)}
                            className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg disabled:opacity-50 disabled:cursor-not-allowed flex items-center space-x-2"
                          >
                            {restoringFiles.has(file.filename) ? (
                              <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin"></div>
                            ) : (
                              <RotateCcw className="w-4 h-4" />
                            )}
                            <span>Restore</span>
                          </button>
                        </td>
                      </tr>
                    ))}
                    {metrics.quarantine_list.length === 0 && (
                      <tr>
                        <td colSpan="3" className="py-3 px-4 text-center text-zinc-500">
                          No files in quarantine
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            </div>
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