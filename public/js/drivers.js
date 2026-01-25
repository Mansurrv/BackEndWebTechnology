document.addEventListener('DOMContentLoaded', async () => {
  const tbody = document.getElementById('drivers-body');

  try {
    const response = await fetch('/api/drivers');
    const drivers = await response.json();

    tbody.innerHTML = '';

    drivers.forEach((driver, index) => {
      const row = document.createElement('tr');

      row.innerHTML = `
        <td>${index + 1}</td>

        <td class="driver-cell">
          <div class="driver-info">
            <img src="${driver.image_url}" class="driver-avatar">
            <span>${driver.name}</span>
          </div>
        </td>

        <td>${driver.team}</td>
        <td class="points">${driver.points}</td>
        <td>${driver.wins}</td>
        <td>${driver.poles}</td>
        <td>${driver.starts}</td>
      `;

      tbody.appendChild(row);
    });
  } catch (err) {
    console.error('Failed to load drivers:', err);
  }
});
