document.addEventListener('DOMContentLoaded', function() {
  const roleSelect = document.getElementById('role');
  const accountGroup = document.getElementById('accountGroup');
  const officerAssignmentGroup = document.getElementById('officerAssignmentGroup');
  const assignedOfficerSelect = document.getElementById('assignedOfficerId');
  const bankName = document.getElementById('bankName');
  const accountName = document.getElementById('accountName');
  const accountNumber = document.getElementById('accountNumber');

  function toggleUserFields() {
    const role = roleSelect.value;
    if (role === 'LoanOfficer') {
      accountGroup.style.display = 'block';
      officerAssignmentGroup.style.display = 'none';
      bankName.required = accountName.required = accountNumber.required = true;
      assignedOfficerSelect.required = false;
    } else if (role === 'Borrower') {
      officerAssignmentGroup.style.display = 'block';
      accountGroup.style.display = 'none';
      assignedOfficerSelect.required = true;
      bankName.required = accountName.required = accountNumber.required = false;
    } else {
      accountGroup.style.display = 'none';
      officerAssignmentGroup.style.display = 'none';
      assignedOfficerSelect.required = false;
      bankName.required = accountName.required = accountNumber.required = false;
    }
  }

  roleSelect.addEventListener('change', toggleUserFields);
  toggleUserFields(); // initialize
});
