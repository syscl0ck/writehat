$(document).ready(function() {

  $('#writehat-engagements').on('click', '.engagementDelete', function(e){

    engagementID = $(e.currentTarget).closest('tr').attr('engagement-id');
    engagementName = $(e.currentTarget).closest('tr').attr('engagement-name');

    promptModal(
      confirm_callback=function(e) {
        $.post({url: `/engagements/delete/${engagementID}`, 
          success: function(result) {
            successRedirect('/engagements', `Successfully deleted engagement: "${engagementName}" and all child entities`);
          }
        })
      },
      title='Delete Engagement?',
      body=`Are you sure you want to delete **${engagementName}** and all of its reports and findings?`,
      leftButtonName='Cancel',
      rightButtonName='Delete Engagement',
      danger=true
    )

  })

  $('#writehat-engagements').on('click', '.engagementClone', function(e){

    engagementID = $(e.currentTarget).closest('tr').attr('engagement-id');
    engagementName = $(e.currentTarget).closest('tr').attr('engagement-name');

    promptModal(
      confirm_callback=function(e) {
        $.post({url: `/engagements/clone/${engagementID}`, 
          success: function(result) {
            successRedirect('/engagements', `Successfully cloned engagement: "${engagementName}"`);
          }
        })
      },
      title='Clone Engagement?',
      body=`Are you sure you want to clone **${engagementName}** and all of its reports and findings?`,
      leftButtonName='Cancel',
      rightButtonName='Clone Engagement',
      danger=false
    )

  })



  $('#writehat-engagements').on('click', '.engagementUpload', function(e){
    e.preventDefault();
    e.stopPropagation();

    engagementID = $(e.currentTarget).closest('tr').attr('engagement-id');
    engagementName = $(e.currentTarget).closest('tr').attr('engagement-name');

    loadModal('engagementFileUpload', function(modal) {
      // Populate report dropdown
      $.post({
        url: `/engagements/${engagementID}/report/list`,
        success: function(reports) {
          var select = $('#id_report_select');
          select.empty();
          select.append('<option value="">Select a report...</option>');
          
          if (reports && reports.length > 0) {
            reports.forEach(function(report) {
              select.append(`<option value="${report.id}">${report.name}</option>`);
            });
          } else {
            select.append('<option value="">No reports available</option>');
          }
        },
        error: function() {
          error('Failed to load reports');
        }
      });

      // Handle form submission
      $('#engagementFileUploadSubmit').off('click').on('click', function() {
        var form = $('#engagementFileUploadForm')[0];
        var formData = new FormData(form);
        var reportID = $('#id_report_select').val();

        if (!reportID) {
          error('Please select a report');
          return;
        }

        formData.append('engagementID', engagementID);
        formData.append('reportID', reportID);

        $.ajax({
          url: '/engagements/fileUpload',
          type: 'POST',
          data: formData,
          processData: false,
          contentType: false,
          success: function(result) {
            success(`Successfully uploaded files for ${engagementName}`);
            $('#engagementFileUpload-modal').modal('hide');
          },
          error: function(xhr) {
            var errorMsg = xhr.responseText || 'Failed to upload files';
            error(errorMsg);
          }
        });
      });

      // Handle cancel
      $('#engagementFileUploadCancel').off('click').on('click', function() {
        $('#engagementFileUpload-modal').modal('hide');
      });

      modal.modal('show');
    }, {engagementID: engagementID});
  });

  /*
  $('.engagementEdit').click(function(e) {

    console.log(e.currentTarget);
    engagementID = $(e.currentTarget).closest('tr').attr('engagement-id');
    window.location.href = '/engagements/edit/' + engagementID;

  });
  */

})