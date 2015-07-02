function restore_options() {
  chrome.storage.sync.get({
    masterPass: 'replace_this',
	passLength: 12
  }, function(items) {
    document.getElementById('master_pass').value = items.masterPass;
    document.getElementById('password_length').value = items.passLength;
  });
}


function save_options() {
  var masterPass = document.getElementById('master_pass').value;
  var passLength = document.getElementById('password_length').value;
  if (passLength<6) passLength=6;
  else if (passLength>256) passLength=256;
  chrome.storage.sync.set({
    masterPass: masterPass,
	passLength: passLength
  }, function() {
    var status = document.getElementById('status');
    status.textContent = 'Options saved.';
    setTimeout(function() {
      status.textContent = '';
    }, 750);
  });
}

document.addEventListener('DOMContentLoaded', restore_options);
document.getElementById('save').addEventListener('click',
    save_options);
