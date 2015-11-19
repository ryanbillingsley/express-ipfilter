module.exports = function(grunt){
  'use strict';

  require('load-grunt-tasks')(grunt);
  grunt.initConfig({
    watch: {
      scripts: {
        files: ['src/**/*.js'],
        tasks: ['test'],
        options: {
          spawn: false
        }
      }
    },
    eslint: {
      all: ['Gruntfile.js', 'lib/**/*.js', 'test/**/*.js']
    },
    'babel': {
      options: {
        sourceMap: true
      },
      dist: {
        files: {
          'lib/ipfilter.js': 'src/ipfilter.js'
        }
      },
      test: {
        files: {
          'test/ipfilter.spec.js': 'src/test/ipfilter.spec.js'
        }
      }
    },
    mocha_istanbul: {
      coverage: {
        src: 'test', // a folder works nicely
        options: {
          mask: '*.spec.js'
        }
      },
    },
  });

  grunt.registerTask('default', ['eslint','babel:dist']);
  grunt.registerTask('test', ['eslint','babel','mocha_istanbul']);
};
