function Header() {
  return (
    <header className="bg-blue-600 text-white p-4 shadow-lg">
      <div className="flex justify-between items-center">
        <h1 className="text-2xl font-bold">Lung Anomaly Detection AI Dashboard</h1>
        <div className="flex items-center space-x-4">
          <div className="bg-green-500 text-white px-3 py-1 rounded-full text-sm">
            System Online
          </div>
          <div className="text-sm">
            Last Update: {new Date().toLocaleTimeString()}
          </div>
        </div>
      </div>
    </header>
  )
}

export default Header

