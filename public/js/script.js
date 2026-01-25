const API = 'http://localhost:3000/api/drivers';

// SHOW
async function getDrivers() {
  const res = await fetch(API);
  const data = await res.json();

  const list = document.getElementById('drivers');
  list.innerHTML = '';

  data.forEach(d => {
    const li = document.createElement('li');
    li.textContent = `${d.id} - ${d.name} (${d.team})`;
    list.appendChild(li);
  });
}

async function addDriver() {
  const body = {
    name: document.getElementById('name').value,
    team: document.getElementById('team').value,
    points: document.getElementById('points').value || 0,
    wins: document.getElementById('wins').value || 0,
    podiums: document.getElementById('podiums').value || 0
  };

  console.log('Sending:', body); // DEBUG

  const res = await fetch(API, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body)
  });

  const data = await res.json();
  console.log('Response:', data);

  if (!res.ok) {
    alert(data.error || 'Failed to add driver');
    return;
  }

  alert('Driver added successfully');
  getDrivers(); // refresh list
}

// DELETE
async function deleteDriver() {
  await fetch(`${API}/${deleteId.value}`, {
    method: 'DELETE'
  });

  alert('Driver deleted');
}

// UPDATE
async function updateDriver() {
  await fetch(`${API}/${updateId.value}`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ points: updatePoints.value })
  });

  alert('Driver updated');
}
