function restore_options() {
  chrome.storage.sync.get({
    masterPass: 'replace_this'
  }, function(items) {
    document.getElementById('master_pass').value = items.masterPass;
  });
}


function save_options() {
  var masterPass = document.getElementById('master_pass').value;
  chrome.storage.sync.set({
    masterPass: masterPass
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
