// src/App.jsx
import React, { useState, useEffect } from "react";

const defaultSettings = {
  alertThreshold: 70,
  dataFolder: "data/preprocessed",
  recursive: true,
  cnnCheckpoint: "runs/cnn/cnn_final.pth",
  unetCheckpoint: "runs/unet/unet_final.pth",
  forceCPU: false,
  displaySize: 512,
};

const placeholderImage = "https://via.placeholder.com/512x512?text=Patient+CT+Scan";

function App() {
  const [settings, setSettings] = useState(defaultSettings);
  const [selectedSlice, setSelectedSlice] = useState(0);
  const [imageList, setImageList] = useState([]);
  const [imageSrc, setImageSrc] = useState(null);

  // Prediction related
  const [detectedConf, setDetectedConf] = useState(0);
  const [predClass, setPredClass] = useState(0);
  const [maskProb, setMaskProb] = useState(null);

  // Event log
  const [eventLog, setEventLog] = useState([]);

  // Simulated effect to load images from folder — replace with backend call
  useEffect(() => {
    // Simulate loading image list (actual your backend should return this)
    const images = [
      "slice1.png",
      "slice2.png",
      "slice3.png",
    ];
    setImageList(images);
    if (images.length > 0) {
      loadImage(images[0]);
    }
  }, []);

  // Simulate loading an image and prediction from backend
  function loadImage(imgName) {
    // For demo: placeholder image, random prediction
    setImageSrc(placeholderImage);
    setPredClass(Math.random() > 0.5 ? 1 : 0);
    const conf = Math.random() * 100;
    setDetectedConf(conf);
    setMaskProb(null); // Placeholder, could be an overlay mask in future

    // Append to event log
    const timeStr = new Date().toLocaleTimeString();
    const logEntry = `${timeStr} | ${imgName} | ${predClass === 1 ? "Anomaly" : "Normal"} (${conf.toFixed(1)}%)`;
    setEventLog((logs) => {
      if (logs.length === 0 || logs[logs.length - 1] !== logEntry) {
        return [...logs, logEntry].slice(-50); // keep last 50
      }
      return logs;
    });
  }

  // Handle slice change
  function handleSliceChange(idx) {
    setSelectedSlice(idx);
    loadImage(imageList[idx]);
  }

  // Handle control changes
  function onChangeSetting(key, value) {
    setSettings((prev) => ({ ...prev, [key]: value }));
  }

  return (
    <div style={{ display: "flex", height: "100vh", fontFamily: "Arial, sans-serif", background: "#161F26", color: "#B5EAFF" }}>
      {/* Sidebar */}
      <aside style={{ width: 280, padding: 20, background: "#19232d", boxSizing: "border-box", display: "flex", flexDirection: "column" }}>
        <h2>Settings</h2>

        <label>
          Alert Threshold (%)<br />
          <input
            type="range"
            min={0}
            max={100}
            value={settings.alertThreshold}
            onChange={(e) => onChangeSetting("alertThreshold", parseInt(e.target.value))}
          />
          <div>{settings.alertThreshold}%</div>
          
        </label>

        
        <label>s
          INPUT<br />
          <input
            type="file"
            onChange={(e) => {
              const file = e.target.files[0];
              if (file) {
                // You can now access the selected file, e.g., get its name or path
                const fileName = file.name;
                onChangeSetting("dataFolder", fileName);
                // In a real app, you would handle this file,
                // e.g., send it to a server for processing.
              }
            }}
            style={{ width: "100%" }}
          />
        </label>
        {/*<label>
          Recursive Search<br />
          <input
            type="checkbox"
            checked={settings.recursive}
            onChange={(e) => onChangeSetting("recursive", e.target.checked)}
          />
        </label>

        <h3>Model Checkpoints</h3>


        {/*<label>
          CNN (.pth)<br />
          <input
            type="text"
            value={settings.cnnCheckpoint}
            onChange={(e) => onChangeSetting("cnnCheckpoint", e.target.value)}
            style={{ width: "100%" }}
          />
        </label>

        <label>
          U-Net (.pth)<br />
          <input
            type="text"
            value={settings.unetCheckpoint}
            onChange={(e) => onChangeSetting("unetCheckpoint", e.target.value)}
            style={{ width: "100%" }}
          />
        </label>

        <label>
          Force CPU<br />
          <input
            type="checkbox"
            checked={settings.forceCPU}
            onChange={(e) => onChangeSetting("forceCPU", e.target.checked)}
          />
        </label>*/}


        {/*<label>
          Display Size (px)<br />
          <input
            type="range"
            min={256}
            max={1024}
            step={32}
            value={settings.displaySize}
            onChange={(e) => onChangeSetting("displaySize", parseInt(e.target.value))}
          />
          <div>{settings.displaySize}px</div>
        </label>*/}

        <hr style={{ marginTop: "auto" }}  />

        <div>Upload PNG,DICOM, MHD image</div>
      </aside>

      {/* Main content */}
      <main style={{ flex: 1, display: "flex", flexDirection: "column", padding: 20, gap: 16, overflowY: "auto" }}>
        <section style={{ display: "flex", flex: 1, gap: 16 }}>
          {/* Image and slice selector */}
          
          <div style={{ flex: 2, background: "#1A232B", borderRadius: 8, padding: 12, boxSizing: "border-box" }}>
            <h2>Patient CT Scan</h2>
            {imageSrc ? (
              <img
                src={imageSrc}
                alt="CT Scan"
                style={{ width: settings.displaySize, height: settings.displaySize, objectFit: "contain", borderRadius: 6 }}
              />
              
            ) : (

               
              <div>No Image Available</div>
            )}{/*
              <div style={{ marginTop: 8 }}>
                <div>Slice: {selectedSlice} / {imageList.length - 1}</div>
                <input
                  type="range"
                  min={0}
                  max={imageList.length - 1}
                  value={selectedSlice}
                  onChange={(e) => handleSliceChange(Number(e.target.value))}
                  disabled={imageList.length === 0}
                  style={{ width: "100%" }}
                />
              </div> */}
          </div>
          

          {/* Alerts and metrics side */}
          <div style={{ flex: 1, background: "#1A232B", borderRadius: 8, padding: 12, boxSizing: "border-box" }}>
            <h2>ALERT</h2>
            {detectedConf === 0 ? (
              <div style={{ color: "#87B6C8" }}>Load an image to see predictions.</div>
            ) : detectedConf > settings.alertThreshold ? (
              <div style={{ color: "#ED4D40", fontWeight: "bold", fontSize: 18 }}>
                CRITICAL: Anomaly detected ({detectedConf.toFixed(1)}%)
              </div>
            ) : (
              <div style={{ color: "#3BD171", fontWeight: "bold", fontSize: 18 }}>
                Normal ({(100 - detectedConf).toFixed(1)}% confidence for normal)
              </div>
            )}

            <h2 style={{ marginTop: 24 }}>METRICS</h2>
            <div style={{ display: "flex", justifyContent: "space-around", gap: 8 }}>
              <Metric label="Confidence (Anomaly)" value={`${detectedConf.toFixed(1)}%`} />
              <Metric label="IoU" value={maskProb ? "0.85" : "—"} />
              <Metric label="Dice" value={maskProb ? "0.88" : "—"} />
            </div>
          </div>
        </section>

        {/* Event Log */}
        <section style={{ background: "#11202E", borderRadius: 8, padding: 12, boxSizing: "border-box", maxHeight: 180, overflowY: "auto" }}>
          <h2>Event Log</h2>
          {eventLog.length === 0 ? (
            <div>No events yet.</div>
          ) : (
            <ul style={{ paddingLeft: 16, margin: 0 }}>
              {eventLog.map((log, i) => (
                <li key={i} style={{ marginBottom: 4, fontSize: 14 }}>
                  {log}
                </li>
              ))}
            </ul>
          )}
        </section>

        <footer style={{ marginTop: 10, fontSize: 12, color: "#87B6C8" }}>
          Tip: If checkpoints are missing, the app runs in demo mode with random weights. Train models or select custom checkpoints in Settings.
        </footer>
      </main>
    </div>
  );
}

function Metric({ label, value }) {
  return (
    <div style={{ flex: 1, background: "#243E53", borderRadius: 8, padding: 12, textAlign: "center" }}>
      <div style={{ fontWeight: "bold", fontSize: 16, marginBottom: 8 }}>{label}</div>
      <div style={{ fontSize: 18 }}>{value}</div>
    </div>
  );
}

export default App;
