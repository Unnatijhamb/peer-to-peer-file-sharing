function StatCard({ title, value, color, icon }) {
  return (
    <div className="bg-white rounded-lg shadow-md p-6 border-l-4" style={{ borderLeftColor: color }}>
      <div className="flex items-center">
        <div className="flex-1">
          <p className="text-sm font-medium text-gray-600 uppercase tracking-wider">{title}</p>
          <p className="mt-2 text-3xl font-bold text-gray-900">{value}</p>
        </div>
        <div className="text-4xl" style={{ color: color }}>{icon}</div>
      </div>
    </div>
  )
}

export default StatCard
