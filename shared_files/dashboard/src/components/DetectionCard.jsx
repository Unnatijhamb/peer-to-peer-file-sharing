function DetectionCard({ patientId, confidence, anomalyType, timestamp, status }) {
  const statusColors = {
    'High Risk': 'bg-red-100 text-red-800',
    'Medium Risk': 'bg-yellow-100 text-yellow-800',
    'Normal': 'bg-green-100 text-green-800'
  }

  return (
    <div className="bg-white rounded-lg shadow-md p-4 border border-gray-200">
      <div className="flex justify-between items-start mb-3">
        <h3 className="text-lg font-semibold text-gray-900">Patient #{patientId}</h3>
        <span className={`px-2 py-1 rounded-full text-xs font-medium ${statusColors[status]}`}>
          {status}
        </span>
      </div>
      <div className="space-y-2">
        <div className="flex justify-between">
          <span className="text-sm text-gray-600">Confidence:</span>
          <span className="text-sm font-medium">{confidence}%</span>
        </div>
        <div className="flex justify-between">
          <span className="text-sm text-gray-600">Anomaly Type:</span>
          <span className="text-sm font-medium">{anomalyType}</span>
        </div>
        <div className="flex justify-between">
          <span className="text-sm text-gray-600">Detected:</span>
          <span className="text-sm font-medium">{timestamp}</span>
        </div>
      </div>
      <div className="mt-3 w-full bg-gray-200 rounded-full h-2">
        <div 
          className="bg-blue-600 h-2 rounded-full" 
          style={{ width: `${confidence}%` }}
        ></div>
      </div>
    </div>
  )
}

export default DetectionCard
