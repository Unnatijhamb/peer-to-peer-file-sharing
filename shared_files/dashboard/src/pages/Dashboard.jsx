import { useState, useEffect } from 'react'
import StatCard from './components/StatCard'
import DetectionCard from './components/DetectionCard'

function Dashboard() {
  const [detections, setDetections] = useState([])
  const [stats, setStats] = useState({
    totalScans: 1247,
    anomaliesDetected: 89,
    normalScans: 1158,
    activePatients: 45
  })

  // Simulate real-time data updates
  useEffect(() => {
    const mockDetections = [
      {
        id: 1,
        patientId: 'P001234',
        confidence: 92,
        anomalyType: 'Nodule',
        timestamp: '10:30 AM',
        status: 'High Risk'
      },
      {
        id: 2,
        patientId: 'P001235',
        confidence: 67,
        anomalyType: 'Inflammation',
        timestamp: '10:25 AM',
        status: 'Medium Risk'
      },
      {
        id: 3,
        patientId: 'P001236',
        confidence: 23,
        anomalyType: 'None',
        timestamp: '10:20 AM',
        status: 'Normal'
      },
      {
        id: 4,
        patientId: 'P001237',
        confidence: 85,
        anomalyType: 'Mass',
        timestamp: '10:15 AM',
        status: 'High Risk'
      }
    ]
    setDetections(mockDetections)
  }, [])

  return (
    <main className="flex-1 p-6 overflow-y-auto">
      <div className="mb-8">
        <h2 className="text-3xl font-bold text-gray-900 mb-2">Dashboard Overview</h2>
        <p className="text-gray-600">Real-time lung anomaly detection results</p>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
        <StatCard 
          title="Total Scans"
          value={stats.totalScans}
          color="#3B82F6"
          icon="🫁"
        />
        <StatCard 
          title="Anomalies Detected"
          value={stats.anomaliesDetected}
          color="#EF4444"
          icon="⚠️"
        />
        <StatCard 
          title="Normal Scans"
          value={stats.normalScans}
          color="#10B981"
          icon="✅"
        />
        <StatCard 
          title="Active Patients"
          value={stats.activePatients}
          color="#F59E0B"
          icon="👥"
        />
      </div>

      {/* Recent Detections */}
      <div className="bg-white rounded-lg shadow-md p-6">
        <div className="flex justify-between items-center mb-6">
          <h3 className="text-xl font-semibold text-gray-900">Recent Detections</h3>
          <button className="bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700 transition-colors">
            View All
          </button>
        </div>
        
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4">
          {detections.map((detection) => (
            <DetectionCard
              key={detection.id}
              patientId={detection.patientId}
              confidence={detection.confidence}
              anomalyType={detection.anomalyType}
              timestamp={detection.timestamp}
              status={detection.status}
            />
          ))}
        </div>
      </div>

      {/* Upload Section */}
      <div className="mt-8 bg-white rounded-lg shadow-md p-6">
        <h3 className="text-xl font-semibold text-gray-900 mb-4">Upload New Scan</h3>
        <div className="border-2 border-dashed border-gray-300 rounded-lg p-8 text-center">
          <div className="text-6xl text-gray-400 mb-4">📁</div>
          <p className="text-gray-600 mb-4">Drag and drop CT scan images here, or click to browse</p>
          <button className="bg-blue-600 text-white px-6 py-2 rounded-lg hover:bg-blue-700 transition-colors">
            Select Files
          </button>
        </div>
      </div>
    </main>
  )
}

export default Dashboard

