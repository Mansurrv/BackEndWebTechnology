const API = '/api/products';

// SHOW
async function getProducts() {
  const res = await fetch(API);
  const data = await res.json();

  const list = document.getElementById('products');
  list.innerHTML = '';

  data.products.forEach(p => {
    const li = document.createElement('li');
    li.textContent = `${p.id}: ${p.name} - $${p.price}`;
    list.appendChild(li);
  });
}

// ADD
async function addProduct() {
  const body = {
    name: document.getElementById('name').value,
    price: parseFloat(document.getElementById('price').value)
  };

  const res = await fetch(API, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body)
  });

  const data = await res.json();
  if (!res.ok) return alert(data.error);
  alert('Product added');
  getProducts();
}

// UPDATE
async function updateProduct() {
  const id = document.getElementById('updateId').value;
  const body = {
    name: document.getElementById('updateName').value || undefined,
    price: parseFloat(document.getElementById('updatePrice').value) || undefined
  };

  const res = await fetch(`${API}/${id}`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body)
  });

  const data = await res.json();
  if (!res.ok) return alert(data.error);
  alert('Product updated');
  getProducts();
}

// DELETE
async function deleteProduct() {
  const id = document.getElementById('deleteId').value;

  const res = await fetch(`${API}/${id}`, { method: 'DELETE' });
  const data = await res.json();
  if (!res.ok) return alert(data.error);
  alert('Product deleted');
  getProducts();
}
