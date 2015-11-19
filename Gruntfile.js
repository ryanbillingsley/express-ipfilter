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
    copy: {
      ci: {
        files: [
          { expand: true, src: 'test-results.xml', dest: process.env.CIRCLE_TEST_REPORTS+'/mocha/' }
        ]
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
    mochaTest: {
      ci: {
        src: 'test/**/*.js',
        options: {
          reporter: 'mocha-junit-reporter'
        }
      }
    },
    mocha_istanbul: {
      coverage: {
        src: 'test',
        options: {
          mask: '*.spec.js'
        }
      },
      ci: {
        src: 'test',
        options: {
          mask: '*.spec.js',
        }
      }
    },
  });

  grunt.registerTask('default', ['eslint','babel:dist']);
  grunt.registerTask('test', ['eslint','babel','mocha_istanbul']);
  grunt.registerTask('ci', ['eslint','babel','mochaTest:ci','mocha_istanbul:ci','copy:ci']);
};
