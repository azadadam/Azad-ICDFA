jQuery( function( $ ) {
	if ( typeof( collapsible_widget_area ) === 'undefined' ) {
		collapsible_widget_area = { '1' : { 'type' : 'tabbed' } };
	}
	
	for ( var i in collapsible_widget_area ) {
		
		if ( collapsible_widget_area[i].type == 'accordion' ) {
			$( '#' + collapsible_widget_area[i].id + ' .collapsible-item .widgettitle' ).each( function() {
				$( this ).html( $( this ).text() );
				$( this ).wrapInner( '<a href="#' + $( this ).closest( '.collapsible-item' ).attr( 'id' ) + '"/>' );
				$( this ).insertBefore( $( this ).closest( '.collapsible-item' ) );
			} );
			$( '#' + collapsible_widget_area[i].id + ' .widgettitle' ).first().addClass( 'first-tab' );
			$( '#' + collapsible_widget_area[i].id + ' .widgettitle' ).last().addClass( 'last-tab' );
			
			var ciwa_accordion_opts = {};
			ciwa_accordion_opts.collapsible = collapsible_widget_area[i].collapsible;
			ciwa_accordion_opts.active = collapsible_widget_area[i].closed ? false : 0;
			
			/*console.log( 'Preparing to turn #collapsible-widget-container-' + i + ' into an accordion' );
			console.log( ciwa_accordion_opts );*/
			
			$( '#' + collapsible_widget_area[i].id ).accordion( ciwa_accordion_opts );
		} else {
			var collapsibleIDs = 0;
			$( '#' + collapsible_widget_area[i].id ).prepend( '<ul class="tab-nav"/>' );
			$( '#' + collapsible_widget_area[i].id + ' .collapsible-item .widgettitle' ).each( function() {
				$( this ).wrapInner( '<a href="#' + $( this ).closest( '.collapsible-item' ).attr( 'id' ) + '"/>' );
				$( this ).wrap( '<li/>' );
				var currentItem = $( this ).find( 'a' );
				$( currentItem ).unwrap();
				$( currentItem ).closest( 'li' ).appendTo( $( currentItem ).closest( '.collapsible-widget-container' ).find( '.tab-nav' ) );
			} );
			$( '#' + collapsible_widget_area[i].id + ' .tab-nav li' ).first().addClass( 'first-tab' );
			$( '#' + collapsible_widget_area[i].id + ' .tab-nav li' ).last().addClass( 'last-tab' );
			
			var ciwa_tab_opts = {};
			if ( collapsible_widget_area[i].cookie ) {
				ciwa_tab_opts.cookie = true;
			}
			
			/*console.log( 'Preparing to turn #collapsible-widget-container-' + i + ' into a tabbed interface' );
			console.log( ciwa_tab_opts );*/
			
			$( '#' + collapsible_widget_area[i].id ).tabs( ciwa_tab_opts );
		}
	}
} );