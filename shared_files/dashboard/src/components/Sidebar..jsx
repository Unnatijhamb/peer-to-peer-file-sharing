function Sidebar() {
  return (
    <aside className="w-64 bg-gray-800 text-white min-h-full shadow-lg">
      <div className="p-4">
        <h2 className="text-lg font-semibold mb-6 text-gray-200">Navigation</h2>
        <nav>
          <ul className="space-y-2">
            <li>
              <a href="#" className="block p-3 rounded-lg bg-blue-600 text-white hover:bg-blue-700 transition-colors">
                Dashboard
              </a>
            </li>
            <li>
              <a href="#" className="block p-3 rounded-lg text-gray-300 hover:bg-gray-700 hover:text-white transition-colors">
                Detection History
              </a>
            </li>
            <li>
              <a href="#" className="block p-3 rounded-lg text-gray-300 hover:bg-gray-700 hover:text-white transition-colors">
                Analytics
              </a>
            </li>
            <li>
              <a href="#" className="block p-3 rounded-lg text-gray-300 hover:bg-gray-700 hover:text-white transition-colors">
                Reports
              </a>
            </li>
            <li>
              <a href="#" className="block p-3 rounded-lg text-gray-300 hover:bg-gray-700 hover:text-white transition-colors">
                Settings
              </a>
            </li>
          </ul>
        </nav>
      </div>
    </aside>
  )
}

export default Sidebar

