// Draw the dial's tick marks (decorative)
(function drawTicks() {
  const g = document.getElementById('ticks');
  if (!g) return;
  const cx = 140, cy = 140, r1 = 120, r2 = 108;
  for (let i = 0; i < 24; i++) {
    const angle = (i / 24) * Math.PI * 2;
    const major = i % 6 === 0;
    const x1 = cx + Math.cos(angle) * r1;
    const y1 = cy + Math.sin(angle) * r1;
    const x2 = cx + Math.cos(angle) * (major ? r2 - 8 : r2);
    const y2 = cy + Math.sin(angle) * (major ? r2 - 8 : r2);
    const line = document.createElementNS('http://www.w3.org/2000/svg', 'line');
    line.setAttribute('x1', x1); line.setAttribute('y1', y1);
    line.setAttribute('x2', x2); line.setAttribute('y2', y2);
    line.setAttribute('class', major ? 'dial-tick major' : 'dial-tick');
    g.appendChild(line);
  }
})();

const forms = ['loginForm', 'twoFaForm', 'registerForm', 'recoveryKitView', 'recoverForm'];

function showTab(which) {
  forms.forEach(id => document.getElementById(id).style.display = 'none');
  hideAlert();

  if (which === 'login') {
    document.getElementById('loginForm').style.display = 'block';
    document.getElementById('tabLogin').classList.add('active');
    document.getElementById('tabRegister').classList.remove('active');
  } else if (which === 'register') {
    document.getElementById('registerForm').style.display = 'block';
    document.getElementById('tabRegister').classList.add('active');
    document.getElementById('tabLogin').classList.remove('active');
  } else if (which === 'recover') {
    document.getElementById('recoverForm').style.display = 'block';
  }
}

function showAlert(message, type = 'error') {
  const box = document.getElementById('alertBox');
  box.textContent = message;
  box.className = `alert ${type}`;
}

function hideAlert() {
  const box = document.getElementById('alertBox');
  box.className = 'alert';
  box.textContent = '';
}

if (Api.token()) {
  window.location.href = 'dashboard.html';
}

// ---------- Login ----------

let pendingPreAuthToken = null;

document.getElementById('loginForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  hideAlert();
  const btn = document.getElementById('loginBtn');
  const email = document.getElementById('loginEmail').value.trim();
  const password = document.getElementById('loginPassword').value;

  btn.disabled = true;
  btn.textContent = 'Unlocking...';
  try {
    const result = await Api.login(email, password);

    if (result.requires2fa) {
      pendingPreAuthToken = result.preAuthToken;
      showTab('none');
      document.getElementById('twoFaForm').style.display = 'block';
      document.getElementById('twoFaCode').focus();
      return;
    }

    Api.setToken(result.token, result.email);
    window.location.href = 'dashboard.html';
  } catch (err) {
    showAlert(err.message);
  } finally {
    btn.disabled = false;
    btn.textContent = 'Unlock vault';
  }
});

document.getElementById('twoFaForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  hideAlert();
  const btn = document.getElementById('twoFaBtn');
  const code = document.getElementById('twoFaCode').value.trim();

  btn.disabled = true;
  btn.textContent = 'Verifying...';
  try {
    const result = await Api.verify2fa(pendingPreAuthToken, code);
    Api.setToken(result.token, result.email);
    window.location.href = 'dashboard.html';
  } catch (err) {
    showAlert(err.message);
    btn.disabled = false;
    btn.textContent = 'Verify';
  }
});

// ---------- Register ----------

const regPwField = document.getElementById('regPassword');
regPwField.addEventListener('input', () => {
  const result = PasswordUtils.score(regPwField.value);
  const fill = document.getElementById('regStrengthFill');
  const label = document.getElementById('regStrengthLabel');
  fill.style.width = result.percent + '%';
  fill.style.background = result.score <= 1 ? 'var(--danger)' : result.score <= 3 ? 'var(--accent)' : 'var(--success)';
  label.textContent = regPwField.value ? `Strength: ${result.label}` : 'At least 8 characters.';
});

let pendingAuthResult = null;

document.getElementById('registerForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  hideAlert();
  const btn = document.getElementById('registerBtn');
  const email = document.getElementById('regEmail').value.trim();
  const password = regPwField.value;

  btn.disabled = true;
  btn.textContent = 'Creating...';
  try {
    const result = await Api.register(email, password);
    pendingAuthResult = result;

    forms.forEach(id => document.getElementById(id).style.display = 'none');
    document.getElementById('recoveryCodeDisplay').textContent = result.recoveryCode;
    document.getElementById('recoveryKitView').style.display = 'block';
  } catch (err) {
    showAlert(err.message);
  } finally {
    btn.disabled = false;
    btn.textContent = 'Create vault';
  }
});

document.getElementById('recoverySavedCheck').addEventListener('change', (e) => {
  document.getElementById('continueToVaultBtn').disabled = !e.target.checked;
});

document.getElementById('continueToVaultBtn').addEventListener('click', () => {
  Api.setToken(pendingAuthResult.token, pendingAuthResult.email);
  window.location.href = 'dashboard.html';
});

// ---------- Account recovery ----------

document.getElementById('recoverForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  hideAlert();
  const btn = document.getElementById('recoverBtn');
  const email = document.getElementById('recoverEmail').value.trim();
  const code = document.getElementById('recoverCode').value.trim();
  const newPassword = document.getElementById('recoverNewPassword').value;

  btn.disabled = true;
  btn.textContent = 'Recovering...';
  try {
    const result = await Api.recoverAccount(email, code, newPassword);
    Api.setToken(result.token, result.email);
    window.location.href = 'dashboard.html';
  } catch (err) {
    showAlert(err.message);
  } finally {
    btn.disabled = false;
    btn.textContent = 'Recover account';
  }
});
