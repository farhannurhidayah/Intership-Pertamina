import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';

function Inputdatasupir({ formData = {}, setFormData }) {
  const navigate = useNavigate();
  const [userId, setUserId] = useState('');

  useEffect(() => {
    // Ambil id user dari localStorage
    const storedUserId = localStorage.getItem('id');
    if (storedUserId) {
      setUserId(storedUserId);
    }
  }, []);

  const handleChange = (e) => {
    setFormData({ ...formData, [e.target.name]: e.target.value });
  };

  return (
    <div className="flex flex-col items-center justify-center h-screen p-4 bg-gray-100">
      <div className="w-full max-w-md p-6 bg-white rounded-lg shadow-md">
        <h2 className="text-2xl font-bold mb-4 text-gray-800">Halaman Trasportir</h2>
        
        {/* Menampilkan id user */}
        <p className="mb-4 text-gray-600">ID User: {userId}</p>
        
        <input
          type="text"
          name="nama_sopir"
          placeholder="Nama Sopir"
          value={formData.nama_sopir || ''}
          onChange={handleChange}
          className="w-full p-3 mb-4 border border-gray-300 rounded-lg"
        />
        <input
          type="number"
          name="nomer_LO"
          placeholder="Nomor LO"
          value={formData.nomer_LO || ''}
          onChange={handleChange}
          className="w-full p-3 mb-4 border border-gray-300 rounded-lg"
        />
        <div className="flex justify-between mt-4">
          <button
            onClick={() => navigate('/halaman2')}
            className="px-4 py-2 bg-blue-500 text-white rounded-lg hover:bg-blue-600"
          >
            Next
          </button>
        </div>
      </div>
    </div>
  );
}

export default Inputdatasupir;
